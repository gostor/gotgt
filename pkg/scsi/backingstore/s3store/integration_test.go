//go:build s3integration

package s3store

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/config"
	"github.com/gostor/gotgt/pkg/scsi"
)

// startFakeS3Server starts an in-process S3-compatible HTTP server using gofakes3.
func startFakeS3Server(t *testing.T) (*httptest.Server, *s3.Client) {
	t.Helper()

	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			"accesskey", "secretkey", "",
		)),
	)
	if err != nil {
		t.Fatalf("failed to load AWS config: %v", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(ts.URL)
		o.UsePathStyle = true
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})

	return ts, client
}

func TestIntegration_FullLifecycle(t *testing.T) {
	ts, client := startFakeS3Server(t)
	defer ts.Close()

	bucket := fmt.Sprintf("gotgt-test-%d", rand.Int63())
	prefix := "integration/disk0"

	// Create bucket
	_, err := client.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("failed to create bucket: %v", err)
	}

	deviceSize := uint64(1024 * 1024) // 1 MiB
	chunkSize := int64(64 * 1024)     // 64 KiB

	// Create and open a new S3-backed device
	bs := &S3BackingStore{
		BaseBackingStore: scsi.BaseBackingStore{Name: S3BackingStorage},
		client:           client,
	}
	dev := &api.SCSILu{
		BackendConfig: &config.BackendStorage{
			DeviceSize:  deviceSize,
			S3ChunkSize: chunkSize,
		},
	}

	path := fmt.Sprintf("%s/%s", bucket, prefix)
	if err := bs.Open(dev, path); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if bs.Size(dev) != deviceSize {
		t.Fatalf("expected size=%d, got %d", deviceSize, bs.Size(dev))
	}

	// Write data at offset 0
	pattern1 := make([]byte, 1000)
	for i := range pattern1 {
		pattern1[i] = byte(i % 251)
	}
	if err := bs.Write(pattern1, 0); err != nil {
		t.Fatalf("Write pattern1 failed: %v", err)
	}

	// Write across chunk boundary
	pattern2 := make([]byte, chunkSize+100)
	for i := range pattern2 {
		pattern2[i] = byte((i + 37) % 251)
	}
	offset2 := chunkSize - 50
	if err := bs.Write(pattern2, offset2); err != nil {
		t.Fatalf("Write pattern2 failed: %v", err)
	}

	// Read back pattern1
	data1, err := bs.Read(0, 1000)
	if err != nil {
		t.Fatalf("Read pattern1 failed: %v", err)
	}
	if !bytes.Equal(data1, pattern1) {
		t.Fatal("pattern1 data mismatch")
	}

	// Read back pattern2
	data2, err := bs.Read(offset2, int64(len(pattern2)))
	if err != nil {
		t.Fatalf("Read pattern2 failed: %v", err)
	}
	if !bytes.Equal(data2, pattern2) {
		t.Fatal("pattern2 data mismatch")
	}

	// Read sparse region (should be zeros)
	sparseOffset := int64(deviceSize) - 1000
	dataSparse, err := bs.Read(sparseOffset, 1000)
	if err != nil {
		t.Fatalf("Read sparse failed: %v", err)
	}
	for i, b := range dataSparse {
		if b != 0 {
			t.Fatalf("sparse byte %d: expected 0, got %d", i, b)
		}
	}

	// Close and reopen to verify persistence
	if err := bs.Close(dev); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	bs2 := &S3BackingStore{
		BaseBackingStore: scsi.BaseBackingStore{Name: S3BackingStorage},
		client:           client, // same in-memory server
	}
	dev2 := &api.SCSILu{
		BackendConfig: &config.BackendStorage{},
	}
	if err := bs2.Open(dev2, path); err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	if bs2.Size(dev2) != deviceSize {
		t.Fatalf("after reopen: expected size=%d, got %d", deviceSize, bs2.Size(dev2))
	}

	// Verify data persisted
	data1Again, err := bs2.Read(0, 1000)
	if err != nil {
		t.Fatalf("Re-read pattern1 failed: %v", err)
	}
	if !bytes.Equal(data1Again, pattern1) {
		t.Fatal("pattern1 data mismatch after reopen")
	}

	// Test unmap (full chunk)
	if err := bs2.Unmap([]api.UnmapBlockDescriptor{
		{Offset: 0, TL: uint64(chunkSize)},
	}); err != nil {
		t.Fatalf("Unmap failed: %v", err)
	}

	// Read unmapped region - should be zeros
	dataUnmapped, err := bs2.Read(0, 100)
	if err != nil {
		t.Fatalf("Read unmapped failed: %v", err)
	}
	for i, b := range dataUnmapped {
		if b != 0 {
			t.Fatalf("unmapped byte %d: expected 0, got %d", i, b)
		}
	}

	bs2.Close(dev2)
	t.Log("S3 integration test: full lifecycle passed")
}

func TestIntegration_LargeWriteRead(t *testing.T) {
	ts, client := startFakeS3Server(t)
	defer ts.Close()

	bucket := fmt.Sprintf("gotgt-large-%d", rand.Int63())
	_, err := client.CreateBucket(context.Background(), &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("failed to create bucket: %v", err)
	}

	deviceSize := uint64(4 * 1024 * 1024) // 4 MiB
	chunkSize := int64(256 * 1024)        // 256 KiB

	bs := &S3BackingStore{
		BaseBackingStore: scsi.BaseBackingStore{Name: S3BackingStorage},
		client:           client,
	}
	dev := &api.SCSILu{
		BackendConfig: &config.BackendStorage{
			DeviceSize:  deviceSize,
			S3ChunkSize: chunkSize,
		},
	}

	path := fmt.Sprintf("%s/large/disk0", bucket)
	if err := bs.Open(dev, path); err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	// Write 1MiB of data spanning multiple chunks
	writeSize := 1024 * 1024
	data := make([]byte, writeSize)
	for i := range data {
		data[i] = byte(i % 256)
	}

	if err := bs.Write(data, 0); err != nil {
		t.Fatalf("Large write failed: %v", err)
	}

	// Read it back
	readBack, err := bs.Read(0, int64(writeSize))
	if err != nil {
		t.Fatalf("Large read failed: %v", err)
	}
	if !bytes.Equal(readBack, data) {
		t.Fatal("large write/read data mismatch")
	}

	bs.Close(dev)
	t.Log("S3 integration test: large write/read passed")
}
