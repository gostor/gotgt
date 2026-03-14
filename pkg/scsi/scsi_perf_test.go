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

package scsi

import (
	"testing"

	"github.com/gostor/gotgt/pkg/api"
)

// BenchmarkBuildSenseData benchmarks Sense Data building performance
func BenchmarkBuildSenseData(b *testing.B) {
	cmd := &api.SCSICommand{
		SCB: []byte{0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00},
		Device: &api.SCSILu{
			Attrs: api.SCSILuPhyAttribute{
				SenseFormat: false, // Fixed format
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	}
}

// BenchmarkBuildSenseDataDescriptor benchmarks Descriptor Format Sense Data building performance
func BenchmarkBuildSenseDataDescriptor(b *testing.B) {
	cmd := &api.SCSICommand{
		SCB: []byte{0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00},
		Device: &api.SCSILu{
			Attrs: api.SCSILuPhyAttribute{
				SenseFormat: true, // Descriptor format
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	}
}

// BenchmarkGetSCSIReadWriteOffset benchmarks offset calculation performance
func BenchmarkGetSCSIReadWriteOffset(b *testing.B) {
	scb := []byte{0x28, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00} // READ_10 at LBA 0x1000

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = getSCSIReadWriteOffset(scb)
	}
}

// BenchmarkGetSCSIReadWriteCount benchmarks block count calculation performance
func BenchmarkGetSCSIReadWriteCount(b *testing.B) {
	scb := []byte{0x28, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x08, 0x00} // READ_10, 8 blocks

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = getSCSIReadWriteCount(scb)
	}
}

// BenchmarkSCSIDeviceOperation benchmarks SCSI device operation lookup performance
func BenchmarkSCSIDeviceOperation(b *testing.B) {
	lu := &api.SCSILu{}
	deviceType := api.TYPE_DISK
	sbc := NewSBCDevice(deviceType)
	sbc.InitLu(lu)

	opcodes := []api.SCSICommandType{
		api.INQUIRY,         // Must be implemented
		api.READ_CAPACITY,   // Must be implemented
		api.MODE_SENSE,      // Must be implemented
		api.TEST_UNIT_READY, // Must be implemented
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		opcode := opcodes[i%len(opcodes)]
		_ = sbc.PerformCommand(int(opcode))
	}
}

// BenchmarkSCSICommandAlloc benchmarks SCSI command allocation performance
func BenchmarkSCSICommandAlloc(b *testing.B) {
	b.Run("WithAllocation", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = &api.SCSICommand{
				OpCode: byte(i % 256),
				SCB:    make([]byte, 16),
			}
		}
	})

	b.Run("Reuse", func(b *testing.B) {
		b.ReportAllocs()
		cmd := &api.SCSICommand{
			SCB: make([]byte, 16),
		}
		for i := 0; i < b.N; i++ {
			cmd.OpCode = byte(i % 256)
			cmd.Result = 0
		}
	})
}

// BenchmarkSCSICommandTypeSwitch benchmarks SCSI command type switching performance
func BenchmarkSCSICommandTypeSwitch(b *testing.B) {
	opcodes := []api.SCSICommandType{
		api.READ_6, api.READ_10, api.READ_12, api.READ_16,
		api.WRITE_6, api.WRITE_10, api.WRITE_12, api.WRITE_16,
		api.INQUIRY, api.READ_CAPACITY, api.MODE_SENSE,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		opcode := opcodes[i%len(opcodes)]
		switch opcode {
		case api.READ_6, api.READ_10, api.READ_12, api.READ_16:
			// Read operation
		case api.WRITE_6, api.WRITE_10, api.WRITE_12, api.WRITE_16:
			// Write operation
		case api.INQUIRY:
			// Inquiry
		case api.READ_CAPACITY:
			// Read capacity
		case api.MODE_SENSE:
			// Mode sense
		default:
			// Unknown
		}
	}
}
