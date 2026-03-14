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

package scsi_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/config"
	"github.com/gostor/gotgt/pkg/scsi"
	_ "github.com/gostor/gotgt/pkg/scsi/backingstore"
)

func setupBenchTarget(b *testing.B, diskSize int64) (*scsi.SCSITargetService, int, uuid.UUID, func()) {
	b.Helper()

	f, err := os.CreateTemp("", "gotgt-bench-*.img")
	if err != nil {
		b.Fatal(err)
	}
	if err := f.Truncate(diskSize); err != nil {
		os.Remove(f.Name())
		b.Fatal(err)
	}
	f.Close()

	svc := scsi.NewSCSITargetService()
	tgt, err := svc.NewSCSITarget(0, "iscsi", "iqn.bench.target")
	if err != nil {
		os.Remove(f.Name())
		b.Fatal(err)
	}

	// Initialize Devices map if nil (NewSCSITarget gets it from global LUN map which is empty in tests)
	if tgt.Devices == nil {
		tgt.Devices = api.LUNMap{}
	}

	bs := &config.BackendStorage{
		DeviceID: 1000,
		Path:     "file:" + f.Name(),
		Online:   true,
	}
	lu, err := scsi.NewSCSILu(bs)
	if err != nil {
		os.Remove(f.Name())
		b.Fatal(err)
	}
	tgt.Devices[0] = lu

	itnexusID := uuid.New()
	itnexus := &api.ITNexus{ID: itnexusID, Tag: "bench-itn"}
	scsi.AddITNexus(tgt, itnexus)

	cleanup := func() {
		lu.Storage.Close(lu)
		os.Remove(f.Name())
	}
	return svc, tgt.TID, itnexusID, cleanup
}

func makeSCSIReadCmd(itnexusID uuid.UUID, lba uint32, blocks uint16, blockShift uint) *api.SCSICommand {
	scb := make([]byte, 10)
	scb[0] = byte(api.READ_10)
	binary.BigEndian.PutUint32(scb[2:6], lba)
	binary.BigEndian.PutUint16(scb[7:9], blocks)

	bufSize := int(blocks) << blockShift
	return &api.SCSICommand{
		ITNexusID: itnexusID,
		SCB:       scb,
		SCBLength: 10,
		Direction: api.SCSIDataRead,
		InSDBBuffer: &api.SCSIDataBuffer{
			Buffer: make([]byte, bufSize),
			Length: uint32(bufSize),
		},
	}
}

func makeSCSIWriteCmd(itnexusID uuid.UUID, lba uint32, blocks uint16, blockShift uint, data []byte) *api.SCSICommand {
	scb := make([]byte, 10)
	scb[0] = byte(api.WRITE_10)
	binary.BigEndian.PutUint32(scb[2:6], lba)
	binary.BigEndian.PutUint16(scb[7:9], blocks)

	bufSize := int(blocks) << blockShift
	outBuf := make([]byte, bufSize)
	copy(outBuf, data)

	return &api.SCSICommand{
		ITNexusID: itnexusID,
		SCB:       scb,
		SCBLength: 10,
		Direction: api.SCSIDataWrite,
		OutSDBBuffer: &api.SCSIDataBuffer{
			Buffer: outBuf,
			Length: uint32(bufSize),
		},
	}
}

// BenchmarkEndToEndRead benchmarks the full SCSI read path:
// AddCommandQueue -> luPerformCommand -> SBCReadWrite -> bsPerformCommand -> FileBackingStore.Read
func BenchmarkEndToEndRead(b *testing.B) {
	blockShift := uint(9)
	diskSize := int64(100 * 1024 * 1024)

	svc, tid, itnID, cleanup := setupBenchTarget(b, diskSize)
	defer cleanup()

	for _, tc := range []struct {
		name   string
		blocks uint16
	}{
		{"512B", 1},
		{"4KB", 8},
		{"64KB", 128},
		{"256KB", 512},
	} {
		b.Run(tc.name, func(b *testing.B) {
			maxLBA := int(diskSize>>blockShift) - int(tc.blocks)
			b.SetBytes(int64(tc.blocks) << blockShift)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				lba := uint32(i % maxLBA)
				cmd := makeSCSIReadCmd(itnID, lba, tc.blocks, blockShift)
				if err := svc.AddCommandQueue(tid, cmd); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEndToEndWrite benchmarks the full SCSI write path.
func BenchmarkEndToEndWrite(b *testing.B) {
	blockShift := uint(9)
	diskSize := int64(100 * 1024 * 1024)

	svc, tid, itnID, cleanup := setupBenchTarget(b, diskSize)
	defer cleanup()

	for _, tc := range []struct {
		name   string
		blocks uint16
	}{
		{"512B", 1},
		{"4KB", 8},
		{"64KB", 128},
		{"256KB", 512},
	} {
		b.Run(tc.name, func(b *testing.B) {
			writeData := make([]byte, int(tc.blocks)<<blockShift)
			for i := range writeData {
				writeData[i] = byte(i)
			}
			maxLBA := int(diskSize>>blockShift) - int(tc.blocks)

			b.SetBytes(int64(tc.blocks) << blockShift)
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				lba := uint32(i % maxLBA)
				cmd := makeSCSIWriteCmd(itnID, lba, tc.blocks, blockShift, writeData)
				if err := svc.AddCommandQueue(tid, cmd); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEndToEndReadParallel benchmarks concurrent SCSI reads.
func BenchmarkEndToEndReadParallel(b *testing.B) {
	blockShift := uint(9)
	diskSize := int64(100 * 1024 * 1024)
	blocks := uint16(8) // 4KB
	maxLBA := int(diskSize>>blockShift) - int(blocks)

	svc, tid, itnID, cleanup := setupBenchTarget(b, diskSize)
	defer cleanup()

	b.SetBytes(int64(blocks) << blockShift)
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			lba := uint32(i % maxLBA)
			cmd := makeSCSIReadCmd(itnID, lba, blocks, blockShift)
			if err := svc.AddCommandQueue(tid, cmd); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

// BenchmarkEndToEndWriteParallel benchmarks concurrent SCSI writes.
func BenchmarkEndToEndWriteParallel(b *testing.B) {
	blockShift := uint(9)
	diskSize := int64(100 * 1024 * 1024)
	blocks := uint16(8) // 4KB
	maxLBA := int(diskSize>>blockShift) - int(blocks)

	svc, tid, itnID, cleanup := setupBenchTarget(b, diskSize)
	defer cleanup()

	writeData := make([]byte, int(blocks)<<blockShift)
	for i := range writeData {
		writeData[i] = byte(i)
	}

	b.SetBytes(int64(blocks) << blockShift)
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			lba := uint32(i % maxLBA)
			cmd := makeSCSIWriteCmd(itnID, lba, blocks, blockShift, writeData)
			if err := svc.AddCommandQueue(tid, cmd); err != nil {
				b.Fatal(err)
			}
			i++
		}
	})
}

// BenchmarkFileBackingStoreRead isolates file backing store read performance.
func BenchmarkFileBackingStoreRead(b *testing.B) {
	f, err := os.CreateTemp("", "gotgt-bs-bench-*.img")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(f.Name())
	if err := f.Truncate(100 * 1024 * 1024); err != nil {
		b.Fatal(err)
	}
	f.Close()

	bs, err := scsi.NewBackingStore("file")
	if err != nil {
		b.Fatal(err)
	}
	lu := &api.SCSILu{}
	if err := bs.Open(lu, f.Name()); err != nil {
		b.Fatal(err)
	}
	defer bs.Close(lu)

	for _, size := range []int64{512, 4096, 65536, 262144} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			b.SetBytes(size)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				off := int64(i*int(size)) % (100*1024*1024 - size)
				_, err := bs.Read(off, size)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkFileBackingStoreWrite isolates file backing store write performance.
func BenchmarkFileBackingStoreWrite(b *testing.B) {
	f, err := os.CreateTemp("", "gotgt-bs-bench-*.img")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(f.Name())
	if err := f.Truncate(100 * 1024 * 1024); err != nil {
		b.Fatal(err)
	}
	f.Close()

	bs, err := scsi.NewBackingStore("file")
	if err != nil {
		b.Fatal(err)
	}
	lu := &api.SCSILu{}
	if err := bs.Open(lu, f.Name()); err != nil {
		b.Fatal(err)
	}
	defer bs.Close(lu)

	for _, size := range []int64{512, 4096, 65536, 262144} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i)
			}

			b.SetBytes(size)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				off := int64(i*int(size)) % (100*1024*1024 - size)
				if err := bs.Write(data, off); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
