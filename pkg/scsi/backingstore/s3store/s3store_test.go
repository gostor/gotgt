package s3store

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/config"
	"github.com/gostor/gotgt/pkg/scsi"
)

// fakeS3Client is an in-memory S3 client for testing.
type fakeS3Client struct {
	mu      sync.Mutex
	objects map[string][]byte // key -> data
}

func newFakeS3Client() *fakeS3Client {
	return &fakeS3Client{objects: make(map[string][]byte)}
}

func (f *fakeS3Client) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	key := *input.Key
	data, ok := f.objects[key]
	if !ok {
		return nil, &types.NoSuchKey{}
	}

	if input.Range != nil {
		var start, end int64
		_, err := fmt.Sscanf(*input.Range, "bytes=%d-%d", &start, &end)
		if err == nil && start >= 0 && end < int64(len(data)) {
			data = data[start : end+1]
		}
	}

	return &s3.GetObjectOutput{
		Body: io.NopCloser(bytes.NewReader(data)),
	}, nil
}

func (f *fakeS3Client) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	key := *input.Key
	data, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	f.objects[key] = data
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3Client) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.objects, *input.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func newTestStore(client *fakeS3Client, chunkSize int64, deviceSize uint64) *S3BackingStore {
	return &S3BackingStore{
		BaseBackingStore: scsi.BaseBackingStore{
			Name:     S3BackingStorage,
			DataSize: deviceSize,
		},
		client:    client,
		bucket:    "test-bucket",
		prefix:    "test/disk",
		chunkSize: chunkSize,
	}
}

func TestOpen_NewDevice(t *testing.T) {
	client := newFakeS3Client()

	bs := &S3BackingStore{
		BaseBackingStore: scsi.BaseBackingStore{Name: S3BackingStorage},
		client:           client,
	}
	dev := &api.SCSILu{
		BackendConfig: &config.BackendStorage{
			DeviceSize: 1024 * 1024, // 1MiB
		},
	}

	err := bs.Open(dev, "mybucket/myprefix")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if bs.bucket != "mybucket" {
		t.Errorf("expected bucket=mybucket, got %s", bs.bucket)
	}
	if bs.prefix != "myprefix" {
		t.Errorf("expected prefix=myprefix, got %s", bs.prefix)
	}
	if bs.DataSize != 1024*1024 {
		t.Errorf("expected DataSize=1048576, got %d", bs.DataSize)
	}

	// Verify metadata was saved
	if _, ok := client.objects["myprefix/_metadata"]; !ok {
		t.Error("metadata object was not created")
	}
}

func TestOpen_ExistingDevice(t *testing.T) {
	client := newFakeS3Client()
	// Pre-populate metadata
	client.objects["myprefix/_metadata"] = []byte(`{"deviceSize":2097152,"chunkSize":1048576}`)

	bs := &S3BackingStore{
		BaseBackingStore: scsi.BaseBackingStore{Name: S3BackingStorage},
		client:           client,
	}
	dev := &api.SCSILu{
		BackendConfig: &config.BackendStorage{},
	}

	err := bs.Open(dev, "mybucket/myprefix")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if bs.DataSize != 2097152 {
		t.Errorf("expected DataSize=2097152, got %d", bs.DataSize)
	}
	if bs.chunkSize != 1048576 {
		t.Errorf("expected chunkSize=1048576, got %d", bs.chunkSize)
	}
}

func TestOpen_InvalidPath(t *testing.T) {
	bs := &S3BackingStore{
		BaseBackingStore: scsi.BaseBackingStore{Name: S3BackingStorage},
		client:           newFakeS3Client(),
	}
	dev := &api.SCSILu{BackendConfig: &config.BackendStorage{}}

	err := bs.Open(dev, "nobucket")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestRead_SingleChunk(t *testing.T) {
	client := newFakeS3Client()
	bs := newTestStore(client, 1024, 4096)

	// Write a chunk
	chunkData := make([]byte, 1024)
	for i := range chunkData {
		chunkData[i] = 0xAB
	}
	client.objects["test/disk/chunk_0000000000"] = chunkData

	data, err := bs.Read(100, 200)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(data) != 200 {
		t.Fatalf("expected 200 bytes, got %d", len(data))
	}
	for i, b := range data {
		if b != 0xAB {
			t.Fatalf("byte %d: expected 0xAB, got 0x%02X", i, b)
		}
	}
}

func TestRead_CrossChunk(t *testing.T) {
	client := newFakeS3Client()
	bs := newTestStore(client, 100, 1000)

	// Chunk 0: bytes 0-99, fill with 0xAA
	chunk0 := make([]byte, 100)
	for i := range chunk0 {
		chunk0[i] = 0xAA
	}
	client.objects["test/disk/chunk_0000000000"] = chunk0

	// Chunk 1: bytes 100-199, fill with 0xBB
	chunk1 := make([]byte, 100)
	for i := range chunk1 {
		chunk1[i] = 0xBB
	}
	client.objects["test/disk/chunk_0000000001"] = chunk1

	// Read across boundary: 50-149
	data, err := bs.Read(50, 100)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(data) != 100 {
		t.Fatalf("expected 100 bytes, got %d", len(data))
	}

	// First 50 bytes from chunk0 (0xAA)
	for i := 0; i < 50; i++ {
		if data[i] != 0xAA {
			t.Fatalf("byte %d: expected 0xAA, got 0x%02X", i, data[i])
		}
	}
	// Last 50 bytes from chunk1 (0xBB)
	for i := 50; i < 100; i++ {
		if data[i] != 0xBB {
			t.Fatalf("byte %d: expected 0xBB, got 0x%02X", i, data[i])
		}
	}
}

func TestRead_SparseChunk(t *testing.T) {
	client := newFakeS3Client()
	bs := newTestStore(client, 100, 1000)

	// Don't create any chunks - should return zeros
	data, err := bs.Read(0, 100)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte %d: expected 0, got 0x%02X", i, b)
		}
	}
}

func TestWrite_SingleChunk(t *testing.T) {
	client := newFakeS3Client()
	bs := newTestStore(client, 1024, 4096)

	wbuf := []byte{1, 2, 3, 4, 5}
	err := bs.Write(wbuf, 10)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// The chunk should exist now (read-modify-write since it's partial)
	chunk, ok := client.objects["test/disk/chunk_0000000000"]
	if !ok {
		t.Fatal("chunk was not created")
	}
	if len(chunk) != 1024 {
		t.Fatalf("chunk size: expected 1024, got %d", len(chunk))
	}
	// Verify written data
	for i, b := range wbuf {
		if chunk[10+i] != b {
			t.Fatalf("byte %d: expected %d, got %d", 10+i, b, chunk[10+i])
		}
	}
	// Verify zeros around it
	if chunk[9] != 0 || chunk[15] != 0 {
		t.Fatal("surrounding bytes should be zero")
	}
}

func TestWrite_FullChunk(t *testing.T) {
	client := newFakeS3Client()
	bs := newTestStore(client, 8, 64)

	// Write exactly one full chunk
	wbuf := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	err := bs.Write(wbuf, 0)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	chunk := client.objects["test/disk/chunk_0000000000"]
	if !bytes.Equal(chunk, wbuf) {
		t.Fatalf("chunk data mismatch: %v vs %v", chunk, wbuf)
	}
}

func TestWrite_CrossChunk(t *testing.T) {
	client := newFakeS3Client()
	bs := newTestStore(client, 8, 64)

	// Write across chunk boundary (offset 6, len 4 -> chunks 0 and 1)
	wbuf := []byte{0xA1, 0xA2, 0xA3, 0xA4}
	err := bs.Write(wbuf, 6)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify chunk 0: bytes 6-7 should be 0xA1, 0xA2
	chunk0 := client.objects["test/disk/chunk_0000000000"]
	if chunk0[6] != 0xA1 || chunk0[7] != 0xA2 {
		t.Fatalf("chunk0 data mismatch at boundary: %v", chunk0[6:8])
	}

	// Verify chunk 1: bytes 0-1 should be 0xA3, 0xA4
	chunk1 := client.objects["test/disk/chunk_0000000001"]
	if chunk1[0] != 0xA3 || chunk1[1] != 0xA4 {
		t.Fatalf("chunk1 data mismatch at boundary: %v", chunk1[0:2])
	}
}

func TestWriteThenRead(t *testing.T) {
	client := newFakeS3Client()
	bs := newTestStore(client, 100, 1000)

	// Write pattern across chunks
	wbuf := make([]byte, 250)
	for i := range wbuf {
		wbuf[i] = byte(i % 256)
	}
	err := bs.Write(wbuf, 50)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read back
	data, err := bs.Read(50, 250)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if !bytes.Equal(data, wbuf) {
		t.Fatal("read data does not match written data")
	}
}

func TestUnmap_FullChunk(t *testing.T) {
	client := newFakeS3Client()
	bs := newTestStore(client, 100, 1000)

	// Create chunk
	client.objects["test/disk/chunk_0000000001"] = make([]byte, 100)

	err := bs.Unmap([]api.UnmapBlockDescriptor{
		{Offset: 100, TL: 100}, // exactly chunk 1
	})
	if err != nil {
		t.Fatalf("Unmap failed: %v", err)
	}

	if _, ok := client.objects["test/disk/chunk_0000000001"]; ok {
		t.Error("chunk should have been deleted")
	}
}

func TestSize(t *testing.T) {
	bs := newTestStore(newFakeS3Client(), 1024, 8192)
	dev := &api.SCSILu{}
	if bs.Size(dev) != 8192 {
		t.Errorf("expected 8192, got %d", bs.Size(dev))
	}
}
