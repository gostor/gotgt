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
	"encoding/binary"
	"testing"
)

// TestLoginRespBytesFormat verifies Login Response BHS format complies with RFC 7143
func TestLoginRespBytesFormat(t *testing.T) {
	cmd := &ISCSICommand{
		OpCode:       OpLoginResp,
		Transit:      true,
		Cont:         false,
		CSG:          LoginOperationalNegotiation,
		NSG:          FullFeaturePhase,
		ISID:         0x123456789ABC,
		TSIH:         0x1234,
		TaskTag:      0xABCDEF00,
		StatSN:       0x12345678,
		ExpCmdSN:     0x87654321,
		MaxCmdSN:     0x87654421,
		StatusClass:  0,
		StatusDetail: 0,
		RawData:      []byte("TestData"),
	}

	resp := cmd.loginRespBytes()

	// Verify BHS length is at least 48 bytes
	if len(resp) < 48 {
		t.Fatalf("BHS too short: expected at least 48, got %d", len(resp))
	}

	// Byte 0: Opcode
	if resp[0] != byte(OpLoginResp) {
		t.Errorf("Byte 0: expected OpLoginResp(0x23), got 0x%02x", resp[0])
	}

	// Byte 1: Flags
	expectedFlags := byte(0x80 | (byte(LoginOperationalNegotiation&0xff) << 2) | byte(FullFeaturePhase&0xff))
	if resp[1] != expectedFlags {
		t.Errorf("Byte 1: expected 0x%02x, got 0x%02x", expectedFlags, resp[1])
	}

	// Byte 2-3: Version
	if resp[2] != 0 || resp[3] != 0 {
		t.Logf("Byte 2-3 (version): %d, %d", resp[2], resp[3])
	}

	// Byte 4-7: Data Segment Length
	dataLen := binary.BigEndian.Uint32(resp[4:8])
	if dataLen != uint32(len(cmd.RawData)) {
		t.Errorf("Data segment length: expected %d, got %d", len(cmd.RawData), dataLen)
	}

	// Byte 8-13: ISID (6 bytes)
	isid := binary.BigEndian.Uint64(append([]byte{0, 0}, resp[8:14]...))
	if isid != cmd.ISID {
		t.Errorf("ISID: expected 0x%012x, got 0x%012x", cmd.ISID, isid)
	}

	// Byte 14-15: TSIH
	tsih := binary.BigEndian.Uint16(resp[14:16])
	if tsih != cmd.TSIH {
		t.Errorf("TSIH: expected 0x%04x, got 0x%04x", cmd.TSIH, tsih)
	}

	// Byte 16-19: Task Tag
	taskTag := binary.BigEndian.Uint32(resp[16:20])
	if taskTag != cmd.TaskTag {
		t.Errorf("TaskTag: expected 0x%08x, got 0x%08x", cmd.TaskTag, taskTag)
	}

	// Byte 24-27: StatSN
	statSN := binary.BigEndian.Uint32(resp[24:28])
	if statSN != cmd.StatSN {
		t.Errorf("StatSN: expected 0x%08x, got 0x%08x", cmd.StatSN, statSN)
	}

	// Byte 28-31: ExpCmdSN
	expCmdSN := binary.BigEndian.Uint32(resp[28:32])
	if expCmdSN != cmd.ExpCmdSN {
		t.Errorf("ExpCmdSN: expected 0x%08x, got 0x%08x", cmd.ExpCmdSN, expCmdSN)
	}

	// Byte 32-35: MaxCmdSN
	maxCmdSN := binary.BigEndian.Uint32(resp[32:36])
	if maxCmdSN != cmd.MaxCmdSN {
		t.Errorf("MaxCmdSN: expected 0x%08x, got 0x%08x", cmd.MaxCmdSN, maxCmdSN)
	}

	// Byte 36: StatusClass
	if resp[36] != cmd.StatusClass {
		t.Errorf("StatusClass: expected %d, got %d", cmd.StatusClass, resp[36])
	}

	// Byte 37: StatusDetail
	if resp[37] != cmd.StatusDetail {
		t.Errorf("StatusDetail: expected %d, got %d", cmd.StatusDetail, resp[37])
	}

	// Verify data segment
	if len(resp) > 48 {
		data := resp[48:]
		if !bytes.Equal(data, cmd.RawData) {
			t.Errorf("RawData mismatch: expected %v, got %v", cmd.RawData, data)
		}
	}

	// Verify 4-byte alignment
	if len(resp)%4 != 0 {
		t.Errorf("Response not aligned to 4 bytes: length=%d", len(resp))
	}
}

// TestLogoutRespBytesFormat verifies Logout Response BHS format
func TestLogoutRespBytesFormat(t *testing.T) {
	cmd := &ISCSICommand{
		OpCode:   OpLogoutResp,
		TaskTag:  0x12345678,
		StatSN:   0xABCDEF00,
		ExpCmdSN: 0x11223344,
		MaxCmdSN: 0x55667788,
	}

	resp := cmd.logoutRespBytes()

	// Verify length is exactly 48 bytes
	if len(resp) != 48 {
		t.Fatalf("Logout response length: expected 48, got %d", len(resp))
	}

	// Byte 0: Opcode
	if resp[0] != byte(OpLogoutResp) {
		t.Errorf("Byte 0: expected OpLogoutResp(0x26), got 0x%02x", resp[0])
	}

	// Byte 1: Flags (0x80)
	if resp[1] != 0x80 {
		t.Errorf("Byte 1: expected 0x80, got 0x%02x", resp[1])
	}

	// Byte 2: Response (0)
	if resp[2] != 0 {
		t.Errorf("Byte 2: expected 0, got 0x%02x", resp[2])
	}

	// Byte 16-19: Task Tag
	taskTag := binary.BigEndian.Uint32(resp[16:20])
	if taskTag != cmd.TaskTag {
		t.Errorf("TaskTag: expected 0x%08x, got 0x%08x", cmd.TaskTag, taskTag)
	}

	// Byte 24-27: StatSN
	statSN := binary.BigEndian.Uint32(resp[24:28])
	if statSN != cmd.StatSN {
		t.Errorf("StatSN: expected 0x%08x, got 0x%08x", cmd.StatSN, statSN)
	}

	// Byte 28-31: ExpCmdSN
	expCmdSN := binary.BigEndian.Uint32(resp[28:32])
	if expCmdSN != cmd.ExpCmdSN {
		t.Errorf("ExpCmdSN: expected 0x%08x, got 0x%08x", cmd.ExpCmdSN, expCmdSN)
	}

	// Byte 32-35: MaxCmdSN
	maxCmdSN := binary.BigEndian.Uint32(resp[32:36])
	if maxCmdSN != cmd.MaxCmdSN {
		t.Errorf("MaxCmdSN: expected 0x%08x, got 0x%08x", cmd.MaxCmdSN, maxCmdSN)
	}
}

// TestSCSICmdRespBytesFormat verifies SCSI Command Response BHS format
func TestSCSICmdRespBytesFormat(t *testing.T) {
	rawData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	cmd := &ISCSICommand{
		OpCode:          OpSCSIResp,
		Status:          0x00, // GOOD
		SCSIResponse:    0x00,
		TaskTag:         0xABCDEF00,
		StatSN:          0x12345678,
		ExpCmdSN:        0x87654321,
		MaxCmdSN:        0x87654421,
		Resid:           0,
		RawData:         rawData,
		ExpectedDataLen: uint32(len(rawData)),
	}

	resp := cmd.scsiCmdRespBytes()

	// Verify length
	if len(resp) < 48 {
		t.Fatalf("SCSI response too short: expected at least 48, got %d", len(resp))
	}

	// Byte 0: Opcode
	if resp[0] != byte(OpSCSIResp) {
		t.Errorf("Byte 0: expected OpSCSIResp(0x21), got 0x%02x", resp[0])
	}

	// Byte 1: Flags (0x80 = final, no residual)
	if resp[1] != 0x80 {
		t.Errorf("Byte 1: expected 0x80, got 0x%02x", resp[1])
	}

	// Byte 2: SCSI Response
	if resp[2] != 0 {
		t.Errorf("Byte 2 (SCSI Response): expected 0, got %d", resp[2])
	}

	// Byte 3: Status
	if resp[3] != cmd.Status {
		t.Errorf("Byte 3 (Status): expected %d, got %d", cmd.Status, resp[3])
	}

	// 验证数据段
	if len(resp) > 48 {
		data := resp[48:]
		if len(data) >= len(rawData) {
			if !bytes.Equal(data[:len(rawData)], rawData) {
				t.Errorf("RawData mismatch")
			}
		}
	}

	// Verify 4-byte alignment
	if len(resp)%4 != 0 {
		t.Errorf("Response not aligned to 4 bytes: length=%d", len(resp))
	}
}

// TestDataInBytesFormat verifies Data-In response format
func TestDataInBytesFormat(t *testing.T) {
	rawData := make([]byte, 512) // Simulate 512 bytes of data
	for i := range rawData {
		rawData[i] = byte(i % 256)
	}

	cmd := &ISCSICommand{
		OpCode:          OpSCSIIn,
		Final:           true,
		FinalInSeq:      true,
		HasStatus:       true,
		Status:          0x00,
		DataLen:         len(rawData),
		TaskTag:         0x12345678,
		StatSN:          0xABCDEF00,
		ExpCmdSN:        0x11111111,
		MaxCmdSN:        0x22222222,
		DataSN:          0,
		BufferOffset:    0,
		Resid:           0,
		RawData:         rawData,
		ExpectedDataLen: uint32(len(rawData)),
		SCSIOpCode:      0x28, // READ_10
	}

	resp := cmd.dataInBytes()

	// 验证长度
	expectedLen := 48 + len(rawData)
	if len(rawData)%4 != 0 {
		expectedLen += 4 - len(rawData)%4
	}
	if len(resp) != expectedLen {
		t.Fatalf("Data-In response length: expected %d, got %d", expectedLen, len(resp))
	}

	// Byte 0: Opcode
	if resp[0] != byte(OpSCSIIn) {
		t.Errorf("Byte 0: expected OpSCSIIn(0x25), got 0x%02x", resp[0])
	}

	// Byte 1: Flags (0x80 = final, 0x01 = status present)
	expectedFlags := byte(0x80 | 0x01)
	if resp[1] != expectedFlags {
		t.Errorf("Byte 1: expected 0x%02x, got 0x%02x", expectedFlags, resp[1])
	}

	// Byte 3: Status
	if resp[3] != cmd.Status {
		t.Errorf("Byte 3 (Status): expected %d, got %d", cmd.Status, resp[3])
	}

	// 验证数据段
	data := resp[48:]
	if !bytes.Equal(data, rawData) {
		t.Errorf("Data segment mismatch")
	}
}

// TestR2TRespBytesFormat verifies R2T (Ready To Transfer) response format
func TestR2TRespBytesFormat(t *testing.T) {
	cmd := &ISCSICommand{
		OpCode:        OpReady,
		Final:         true,
		TaskTag:       0x12345678,
		StatSN:        0xABCDEF00,
		ExpCmdSN:      0x11111111,
		MaxCmdSN:      0x22222222,
		R2TSN:         0,
		BufferOffset:  0,
		DesiredLength: 8192,
	}

	resp := cmd.r2tRespBytes()

	// Verify length is exactly 48 bytes
	if len(resp) != 48 {
		t.Fatalf("R2T response length: expected 48, got %d", len(resp))
	}

	// Byte 0: Opcode
	if resp[0] != byte(OpReady) {
		t.Errorf("Byte 0: expected OpReady(0x31), got 0x%02x", resp[0])
	}

	// Byte 1: Flags (0x80 = final)
	if resp[1] != 0x80 {
		t.Errorf("Byte 1: expected 0x80, got 0x%02x", resp[1])
	}

	// Byte 16-19: Task Tag
	taskTag := binary.BigEndian.Uint32(resp[16:20])
	if taskTag != cmd.TaskTag {
		t.Errorf("TaskTag: expected 0x%08x, got 0x%08x", cmd.TaskTag, taskTag)
	}

	// Byte 36-39: R2TSN
	r2tsn := binary.BigEndian.Uint32(resp[36:40])
	if r2tsn != cmd.R2TSN {
		t.Errorf("R2TSN: expected 0x%08x, got 0x%08x", cmd.R2TSN, r2tsn)
	}

	// Byte 40-43: Buffer Offset
	bufferOffset := binary.BigEndian.Uint32(resp[40:44])
	if bufferOffset != cmd.BufferOffset {
		t.Errorf("BufferOffset: expected 0x%08x, got 0x%08x", cmd.BufferOffset, bufferOffset)
	}

	// Byte 44-47: Desired Length
	desiredLength := binary.BigEndian.Uint32(resp[44:48])
	if desiredLength != cmd.DesiredLength {
		t.Errorf("DesiredLength: expected 0x%08x, got 0x%08x", cmd.DesiredLength, desiredLength)
	}
}

// BenchmarkLoginRespBytes benchmarks Login Response
func BenchmarkLoginRespBytes(b *testing.B) {
	cmd := &ISCSICommand{
		OpCode:       OpLoginResp,
		Transit:      true,
		ISID:         0x123456789ABC,
		TSIH:         0x1234,
		TaskTag:      0xABCDEF00,
		StatSN:       0x12345678,
		ExpCmdSN:     0x87654321,
		MaxCmdSN:     0x87654421,
		StatusClass:  0,
		StatusDetail: 0,
		RawData:      []byte("TestData"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cmd.loginRespBytes()
	}
}

// TestTextRespBytesFormat verifies Text Response BHS format
func TestTextRespBytesFormat(t *testing.T) {
	rawData := []byte("SendTargets=test")
	cmd := &ISCSICommand{
		OpCode:   OpTextResp,
		Final:    true,
		Cont:     false,
		TaskTag:  0x12345678,
		StatSN:   0xABCDEF00,
		ExpCmdSN: 0x11111111,
		MaxCmdSN: 0x22222222,
		RawData:  rawData,
	}

	resp := cmd.textRespBytes()

	// Verify BHS length is at least 48 bytes
	if len(resp) < 48 {
		t.Fatalf("BHS too short: expected at least 48, got %d", len(resp))
	}

	// Byte 0: Opcode
	if resp[0] != byte(OpTextResp) {
		t.Errorf("Byte 0: expected OpTextResp(0x24), got 0x%02x", resp[0])
	}

	// Byte 1: Flags (0x80 = final)
	if resp[1] != 0x80 {
		t.Errorf("Byte 1: expected 0x80, got 0x%02x", resp[1])
	}

	// Byte 4-7: Data Segment Length
	dataLen := binary.BigEndian.Uint32(resp[4:8])
	if dataLen != uint32(len(rawData)) {
		t.Errorf("Data segment length: expected %d, got %d", len(rawData), dataLen)
	}

	// Byte 16-19: Task Tag
	taskTag := binary.BigEndian.Uint32(resp[16:20])
	if taskTag != cmd.TaskTag {
		t.Errorf("TaskTag: expected 0x%08x, got 0x%08x", cmd.TaskTag, taskTag)
	}

	// Byte 20-23: 0xffffffff
	if resp[20] != 0xff || resp[21] != 0xff || resp[22] != 0xff || resp[23] != 0xff {
		t.Errorf("Bytes 20-23: expected 0xffffffff, got 0x%02x%02x%02x%02x",
			resp[20], resp[21], resp[22], resp[23])
	}

	// Byte 24-27: StatSN
	statSN := binary.BigEndian.Uint32(resp[24:28])
	if statSN != cmd.StatSN {
		t.Errorf("StatSN: expected 0x%08x, got 0x%08x", cmd.StatSN, statSN)
	}

	// 验证数据段
	if len(resp) > 48 {
		data := resp[48:]
		if !bytes.Equal(data, rawData) {
			t.Errorf("RawData mismatch: expected %v, got %v", rawData, data)
		}
	}

	// Verify 4-byte alignment
	if len(resp)%4 != 0 {
		t.Errorf("Response not aligned to 4 bytes: length=%d", len(resp))
	}
}

// BenchmarkSCSICmdRespBytes benchmarks SCSI Command Response
func BenchmarkSCSICmdRespBytes(b *testing.B) {
	cmd := &ISCSICommand{
		OpCode:   OpSCSIResp,
		Status:   0x00,
		TaskTag:  0xABCDEF00,
		StatSN:   0x12345678,
		ExpCmdSN: 0x87654321,
		MaxCmdSN: 0x87654421,
		RawData:  []byte{0x00, 0x01, 0x02, 0x03},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cmd.scsiCmdRespBytes()
	}
}
