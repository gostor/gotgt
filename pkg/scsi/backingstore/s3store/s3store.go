/*
Copyright 2024 The GoStor Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package s3store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/config"
	"github.com/gostor/gotgt/pkg/scsi"
)

const (
	S3BackingStorage = "s3"
	DefaultChunkSize = 4 * 1024 * 1024 // 4 MiB
	metadataKey      = "_metadata"
)

func init() {
	scsi.RegisterBackingStore(S3BackingStorage, newS3)
}

// s3Client is the minimal S3 interface used by this package, enabling test injection.
type s3Client interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// deviceMetadata stores device configuration in S3.
type deviceMetadata struct {
	DeviceSize uint64 `json:"deviceSize"`
	ChunkSize  int64  `json:"chunkSize"`
}

// S3BackingStore implements the BackingStore interface using S3-compatible object storage.
// The virtual block device is divided into fixed-size chunks, each stored as a separate S3 object.
type S3BackingStore struct {
	scsi.BaseBackingStore
	client     s3Client
	bucket     string
	prefix     string
	chunkSize  int64
	chunkLocks sync.Map // map[int64]*sync.Mutex
}

func newS3() (api.BackingStore, error) {
	return &S3BackingStore{
		BaseBackingStore: scsi.BaseBackingStore{
			Name:            S3BackingStorage,
			DataSize:        0,
			OflagsSupported: 0,
		},
	}, nil
}

func (bs *S3BackingStore) lockChunk(idx int64) *sync.Mutex {
	val, _ := bs.chunkLocks.LoadOrStore(idx, &sync.Mutex{})
	mu := val.(*sync.Mutex)
	mu.Lock()
	return mu
}

func (bs *S3BackingStore) chunkKey(idx int64) string {
	return fmt.Sprintf("%s/chunk_%010d", bs.prefix, idx)
}

func (bs *S3BackingStore) metadataObjKey() string {
	return fmt.Sprintf("%s/%s", bs.prefix, metadataKey)
}

func (bs *S3BackingStore) Open(dev *api.SCSILu, path string) error {
	// Parse path: bucket/prefix
	idx := strings.Index(path, "/")
	if idx <= 0 {
		return fmt.Errorf("invalid S3 path %q, expected bucket/prefix", path)
	}
	bs.bucket = path[:idx]
	bs.prefix = path[idx+1:]
	if bs.prefix == "" {
		return fmt.Errorf("invalid S3 path %q, prefix cannot be empty", path)
	}

	// Read backend-specific config
	var (
		chunkSize      int64
		deviceSize     uint64
		endpoint       string
		region         string
		forcePathStyle bool
	)
	if cfg, ok := dev.BackendConfig.(*config.BackendStorage); ok && cfg != nil {
		chunkSize = cfg.S3ChunkSize
		deviceSize = cfg.DeviceSize
		endpoint = cfg.S3Endpoint
		region = cfg.S3Region
		forcePathStyle = cfg.S3ForcePathStyle
	}
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	bs.chunkSize = chunkSize

	// Create S3 client if not already set (e.g., by tests)
	if bs.client == nil {
		ctx := context.Background()
		var opts []func(*awsconfig.LoadOptions) error
		if region != "" {
			opts = append(opts, awsconfig.WithRegion(region))
		}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return fmt.Errorf("failed to load AWS config: %w", err)
		}

		var s3Opts []func(*s3.Options)
		if endpoint != "" {
			s3Opts = append(s3Opts, func(o *s3.Options) {
				o.BaseEndpoint = aws.String(endpoint)
			})
		}
		if forcePathStyle {
			s3Opts = append(s3Opts, func(o *s3.Options) {
				o.UsePathStyle = true
			})
		}
		// Disable response checksum validation for compatibility with
		// S3-compatible backends (e.g., MinIO) and range read requests.
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		})
		bs.client = s3.NewFromConfig(cfg, s3Opts...)
	}

	// Try to load existing metadata
	ctx := context.Background()
	meta, err := bs.loadMetadata(ctx)
	if err != nil {
		var nsk *types.NoSuchKey
		if !errors.As(err, &nsk) {
			return fmt.Errorf("failed to load S3 metadata: %w", err)
		}
		// Metadata does not exist - create new device
		if deviceSize == 0 {
			return fmt.Errorf("S3 device metadata not found and deviceSize not configured")
		}
		meta = &deviceMetadata{
			DeviceSize: deviceSize,
			ChunkSize:  chunkSize,
		}
		if err := bs.saveMetadata(ctx, meta); err != nil {
			return fmt.Errorf("failed to save S3 metadata: %w", err)
		}
		log.Infof("S3 backing store: created new device %s/%s, size=%d, chunkSize=%d",
			bs.bucket, bs.prefix, deviceSize, chunkSize)
	} else {
		bs.chunkSize = meta.ChunkSize
		log.Infof("S3 backing store: opened existing device %s/%s, size=%d, chunkSize=%d",
			bs.bucket, bs.prefix, meta.DeviceSize, meta.ChunkSize)
	}

	bs.DataSize = meta.DeviceSize
	return nil
}

func (bs *S3BackingStore) loadMetadata(ctx context.Context) (*deviceMetadata, error) {
	key := bs.metadataObjKey()
	out, err := bs.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bs.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()

	var meta deviceMetadata
	if err := json.NewDecoder(out.Body).Decode(&meta); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}
	return &meta, nil
}

func (bs *S3BackingStore) saveMetadata(ctx context.Context, meta *deviceMetadata) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	key := bs.metadataObjKey()
	_, err = bs.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bs.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	return err
}

func (bs *S3BackingStore) Close(dev *api.SCSILu) error {
	bs.client = nil
	return nil
}

func (bs *S3BackingStore) Init(dev *api.SCSILu, Opts string) error {
	return nil
}

func (bs *S3BackingStore) Exit(dev *api.SCSILu) error {
	return nil
}

func (bs *S3BackingStore) Size(dev *api.SCSILu) uint64 {
	return bs.DataSize
}

func (bs *S3BackingStore) Read(offset, tl int64) ([]byte, error) {
	if bs.client == nil {
		return nil, fmt.Errorf("S3 backend store is not open")
	}

	result := make([]byte, tl)
	startChunk := offset / bs.chunkSize
	endChunk := (offset + tl - 1) / bs.chunkSize

	ctx := context.Background()
	eg, ctx := errgroup.WithContext(ctx)

	for ci := startChunk; ci <= endChunk; ci++ {
		ci := ci
		eg.Go(func() error {
			chunkStart := ci * bs.chunkSize
			readStart := max(offset, chunkStart) - chunkStart
			readEnd := min(offset+tl, chunkStart+bs.chunkSize) - chunkStart

			data, err := bs.getChunkRange(ctx, ci, readStart, readEnd)
			if err != nil {
				return err
			}

			destStart := max(offset, chunkStart) - offset
			copy(result[destStart:], data)
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, err
	}
	return result, nil
}

// ReadAt reads directly into the provided buffer to avoid allocation.
func (bs *S3BackingStore) ReadAt(buf []byte, offset int64) (int, error) {
	data, err := bs.Read(offset, int64(len(buf)))
	if err != nil {
		return 0, err
	}
	copy(buf, data)
	return len(buf), nil
}

// getChunkRange reads a byte range from a chunk. Returns zeros if the chunk does not exist.
func (bs *S3BackingStore) getChunkRange(ctx context.Context, chunkIdx, start, end int64) ([]byte, error) {
	key := bs.chunkKey(chunkIdx)
	rangeStr := fmt.Sprintf("bytes=%d-%d", start, end-1)

	out, err := bs.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bs.bucket),
		Key:    aws.String(key),
		Range:  aws.String(rangeStr),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			// Chunk doesn't exist - return zeros (sparse)
			return make([]byte, end-start), nil
		}
		return nil, fmt.Errorf("failed to read chunk %d: %w", chunkIdx, err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunk %d body: %w", chunkIdx, err)
	}

	// Pad with zeros if chunk is shorter than expected range
	expected := int(end - start)
	if len(data) < expected {
		padded := make([]byte, expected)
		copy(padded, data)
		return padded, nil
	}
	return data, nil
}

func (bs *S3BackingStore) Write(wbuf []byte, offset int64) error {
	if bs.client == nil {
		return fmt.Errorf("S3 backend store is not open")
	}

	tl := int64(len(wbuf))
	startChunk := offset / bs.chunkSize
	endChunk := (offset + tl - 1) / bs.chunkSize

	ctx := context.Background()
	eg, ctx := errgroup.WithContext(ctx)

	for ci := startChunk; ci <= endChunk; ci++ {
		ci := ci
		eg.Go(func() error {
			chunkStart := ci * bs.chunkSize
			writeStart := max(offset, chunkStart) - chunkStart
			writeEnd := min(offset+tl, chunkStart+bs.chunkSize) - chunkStart

			srcStart := max(offset, chunkStart) - offset
			srcEnd := srcStart + (writeEnd - writeStart)

			if writeStart == 0 && writeEnd == bs.chunkSize {
				// Full chunk write - direct upload
				return bs.putChunk(ctx, ci, wbuf[srcStart:srcEnd])
			}
			// Partial chunk - read-modify-write
			return bs.readModifyWriteChunk(ctx, ci, writeStart, writeEnd, wbuf[srcStart:srcEnd])
		})
	}

	return eg.Wait()
}

func (bs *S3BackingStore) putChunk(ctx context.Context, chunkIdx int64, data []byte) error {
	key := bs.chunkKey(chunkIdx)
	_, err := bs.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bs.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
	})
	if err != nil {
		return fmt.Errorf("failed to write chunk %d: %w", chunkIdx, err)
	}
	return nil
}

func (bs *S3BackingStore) readModifyWriteChunk(ctx context.Context, chunkIdx, writeStart, writeEnd int64, data []byte) error {
	mu := bs.lockChunk(chunkIdx)
	defer mu.Unlock()

	// Read existing chunk
	chunk, err := bs.getFullChunk(ctx, chunkIdx)
	if err != nil {
		return err
	}

	// Modify
	copy(chunk[writeStart:writeEnd], data)

	// Write back
	return bs.putChunk(ctx, chunkIdx, chunk)
}

// getFullChunk reads the full chunk, returning a zero-filled buffer if it doesn't exist.
func (bs *S3BackingStore) getFullChunk(ctx context.Context, chunkIdx int64) ([]byte, error) {
	key := bs.chunkKey(chunkIdx)
	out, err := bs.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bs.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return make([]byte, bs.chunkSize), nil
		}
		return nil, fmt.Errorf("failed to read full chunk %d: %w", chunkIdx, err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read full chunk %d body: %w", chunkIdx, err)
	}

	if int64(len(data)) < bs.chunkSize {
		padded := make([]byte, bs.chunkSize)
		copy(padded, data)
		return padded, nil
	}
	return data, nil
}

func (bs *S3BackingStore) DataSync(offset, tl int64) error {
	// S3 PutObject is durable once acknowledged
	return nil
}

func (bs *S3BackingStore) DataAdvise(offset, length int64, advise uint32) error {
	return nil
}

func (bs *S3BackingStore) Unmap(descriptors []api.UnmapBlockDescriptor) error {
	if bs.client == nil {
		return fmt.Errorf("S3 backend store is not open")
	}

	ctx := context.Background()
	for _, desc := range descriptors {
		startChunk := int64(desc.Offset) / bs.chunkSize
		endChunk := int64(desc.Offset+desc.TL-1) / bs.chunkSize

		for ci := startChunk; ci <= endChunk; ci++ {
			chunkStart := ci * bs.chunkSize
			unmapStart := max(int64(desc.Offset), chunkStart) - chunkStart
			unmapEnd := min(int64(desc.Offset+desc.TL), chunkStart+bs.chunkSize) - chunkStart

			if unmapStart == 0 && unmapEnd == bs.chunkSize {
				// Full chunk unmap - delete the object
				key := bs.chunkKey(ci)
				if _, err := bs.client.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(bs.bucket),
					Key:    aws.String(key),
				}); err != nil {
					return fmt.Errorf("failed to delete chunk %d: %w", ci, err)
				}
			}
			// Partial chunk unmap - ignore (sparse zeros on next read is fine
			// since missing chunk data is treated as zeros)
		}
	}
	return nil
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
