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

package iscsit

import (
	"bytes"
	"testing"
	"time"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/util"
)

// BenchmarkParseHeader benchmarks iSCSI protocol header parsing performance
func BenchmarkParseHeader(b *testing.B) {
	// Build a typical SCSI CDB command header
	header := make([]byte, BHS_SIZE)
	header[0] = byte(OpSCSICmd) // SCSI Command
	header[1] = 0x80            // Final bit
	header[4] = 0               // AHS length
	header[5] = 0
	header[6] = 0
	header[7] = 0 // Data segment length = 0
	// TaskTag at bytes 16-19
	header[16] = 0x00
	header[17] = 0x00
	header[18] = 0x00
	header[19] = 0x01
	// ExpectedDataLen at bytes 20-23
	header[20] = 0x00
	header[21] = 0x00
	header[22] = 0x10
	header[23] = 0x00 // 4096 bytes
	// CmdSN at bytes 24-27
	header[24] = 0x00
	header[25] = 0x00
	header[26] = 0x00
	header[27] = 0x01
	// ExpStatSN at bytes 28-31
	header[28] = 0x00
	header[29] = 0x00
	header[30] = 0x00
	header[31] = 0x01
	// CDB at bytes 32-47 (READ_10 command)
	header[32] = byte(api.READ_10)
	header[33] = 0x00
	header[34] = 0x00
	header[35] = 0x00
	header[36] = 0x00
	header[37] = 0x00 // LBA = 0
	header[38] = 0x00
	header[39] = 0x08 // Transfer length = 8 blocks
	header[40] = 0x00 // Control

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cmd, err := parseHeader(header)
		if err != nil {
			b.Fatal(err)
		}
		_ = cmd
	}
}

// BenchmarkParseHeaderWithPool benchmarks header parsing with object pool
func BenchmarkParseHeaderWithPool(b *testing.B) {
	header := make([]byte, BHS_SIZE)
	header[0] = byte(OpSCSICmd)
	header[1] = 0x80
	header[32] = byte(api.READ_10)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cmd := getCommand()
		cmd.OpCode = OpCode(header[0] & ISCSI_OPCODE_MASK)
		cmd.Final = 0x80&header[1] == 0x80
		cmd.AHSLen = int(header[4]) * 4
		cmd.DataLen = int(ParseUint(header[5:8]))
		cmd.TaskTag = uint32(ParseUint(header[16:20]))
		cmd.CDB = header[32:48]
		cmd.StartTime = time.Now()
		putCommand(cmd)
	}
}

// BenchmarkDataInBytes benchmarks Data-In response serialization performance
func BenchmarkDataInBytes(b *testing.B) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}

	cmd := &ISCSICommand{
		OpCode:       OpSCSIIn,
		Final:        true,
		FinalInSeq:   true,
		TaskTag:      1,
		StatSN:       100,
		ExpCmdSN:     101,
		MaxCmdSN:     200,
		DataLen:      4096,
		DataSN:       0,
		BufferOffset: 0,
		RawData:      data,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cmd.dataInBytes()
	}
}

// BenchmarkDataInBytesSmall benchmarks Data-In performance with small data blocks
func BenchmarkDataInBytesSmall(b *testing.B) {
	data := make([]byte, 512)

	cmd := &ISCSICommand{
		OpCode:       OpSCSIIn,
		Final:        true,
		FinalInSeq:   true,
		TaskTag:      1,
		StatSN:       100,
		ExpCmdSN:     101,
		MaxCmdSN:     200,
		DataLen:      512,
		DataSN:       0,
		BufferOffset: 0,
		RawData:      data,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cmd.dataInBytes()
	}
}

// BenchmarkDataInBytesLarge benchmarks Data-In performance with large data blocks
func BenchmarkDataInBytesLarge(b *testing.B) {
	data := make([]byte, 65536)

	cmd := &ISCSICommand{
		OpCode:       OpSCSIIn,
		Final:        true,
		FinalInSeq:   true,
		TaskTag:      1,
		StatSN:       100,
		ExpCmdSN:     101,
		MaxCmdSN:     200,
		DataLen:      65536,
		DataSN:       0,
		BufferOffset: 0,
		RawData:      data,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cmd.dataInBytes()
	}
}

// BenchmarkBytesComparison compares Bytes() performance for different OpCodes
func BenchmarkBytesComparison(b *testing.B) {
	testCases := []struct {
		name string
		cmd  *ISCSICommand
	}{
		{
			name: "LoginResp",
			cmd: &ISCSICommand{
				OpCode:       OpLoginResp,
				Final:        true,
				Transit:      true,
				CSG:          LoginOperationalNegotiation,
				NSG:          FullFeaturePhase,
				TaskTag:      1,
				StatSN:       0,
				ExpCmdSN:     1,
				MaxCmdSN:     1,
				StatusClass:  0,
				StatusDetail: 0,
				RawData:      []byte("TargetPortalGroupTag=1"),
			},
		},
		{
			name: "SCSIResp",
			cmd: &ISCSICommand{
				OpCode:   OpSCSIResp,
				Final:    true,
				TaskTag:  1,
				StatSN:   100,
				ExpCmdSN: 101,
				MaxCmdSN: 200,
			},
		},
		{
			name: "SCSIIn",
			cmd: &ISCSICommand{
				OpCode:   OpSCSIIn,
				Final:    true,
				TaskTag:  1,
				StatSN:   100,
				ExpCmdSN: 101,
				MaxCmdSN: 200,
				DataLen:  4096,
				RawData:  make([]byte, 4096),
			},
		},
		{
			name: "R2T",
			cmd: &ISCSICommand{
				OpCode:        OpReady,
				Final:         true,
				TaskTag:       1,
				StatSN:        100,
				ExpCmdSN:      101,
				MaxCmdSN:      200,
				R2TSN:         0,
				BufferOffset:  0,
				DesiredLength: 8192,
			},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = tc.cmd.Bytes()
			}
		})
	}
}

// BenchmarkCommandPool benchmarks command object pool performance
func BenchmarkCommandPool(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cmd := getCommand()
			cmd.OpCode = OpSCSICmd
			cmd.TaskTag = uint32(i)
			putCommand(cmd)
		}
	})

	b.Run("WithoutPool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cmd := &ISCSICommand{
				OpCode:  OpSCSICmd,
				TaskTag: uint32(i),
			}
			_ = cmd
		}
	})
}

// BenchmarkBufferPool benchmarks buffer pool performance
func BenchmarkBufferPool(b *testing.B) {
	b.Run("WithPool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := getBuffer()
			buf[0] = byte(i)
			putBuffer(buf)
		}
	})

	b.Run("WithoutPool", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			buf := make([]byte, BHS_SIZE)
			buf[0] = byte(i)
			_ = buf
		}
	})
}

// BenchmarkTaskStateTransition benchmarks task state transition performance
func BenchmarkTaskStateTransition(b *testing.B) {
	task := &iscsiTask{
		tag:   1,
		state: taskPending,
		scmd:  &api.SCSICommand{},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if i%2 == 0 {
			task.state = taskPending
		} else {
			task.state = taskSCSI
		}
	}
}

// BenchmarkParseUint benchmarks ParseUint performance
func BenchmarkParseUint(b *testing.B) {
	testData := []byte{0x00, 0x00, 0x10, 0x00}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ParseUint(testData)
	}
}

// BenchmarkBytesComparisonEqual benchmarks byte comparison performance
func BenchmarkBytesComparisonEqual(b *testing.B) {
	a := make([]byte, 48)
	b2 := make([]byte, 48)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = bytes.Equal(a, b2)
	}
}

// BenchmarkMarshalUint32 benchmarks uint32 serialization performance
func BenchmarkMarshalUint32(b *testing.B) {
	val := uint32(0x12345678)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = util.MarshalUint32(val)
	}
}

// BenchmarkMarshalUint64 benchmarks uint64 serialization performance
func BenchmarkMarshalUint64(b *testing.B) {
	val := uint64(0x1234567890ABCDEF)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = util.MarshalUint64(val)
	}
}

// BenchmarkBuildRespPackage benchmarks complete response package building performance
func BenchmarkBuildRespPackage(b *testing.B) {
	conn := &iscsiConnection{
		state:    CONN_STATE_SCSI,
		statSN:   99,
		expCmdSN: 100,
		loginParam: &iscsiLoginParam{
			sessionParam: []ISCSISessionParam{
				{idx: ISCSI_PARAM_MAX_BURST, Value: 262144},
			},
		},
		session: &ISCSISession{
			ExpCmdSN:        100,
			MaxQueueCommand: 32,
		},
		req: &ISCSICommand{
			OpCode:          OpSCSICmd,
			TaskTag:         1,
			ExpStatSN:       100,
			ExpectedDataLen: 4096,
			StartTime:       time.Now(),
		},
		rxTask: &iscsiTask{
			tag: 1,
			scmd: &api.SCSICommand{
				Result:    0,
				Direction: api.SCSIDataRead,
				InSDBBuffer: &api.SCSIDataBuffer{
					Buffer: make([]byte, 4096),
					Length: 4096,
				},
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = conn.buildRespPackage(OpSCSIResp, nil)
	}
}
