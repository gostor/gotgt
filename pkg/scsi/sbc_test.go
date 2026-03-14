/*
Copyright 2015 The GoStor Authors All rights reserved.

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

// SCSI block command processing
package scsi

import (
	"testing"

	"github.com/gostor/gotgt/pkg/api"
)

func TestSBCModeSelect(t *testing.T) {
}

func TestSBCModeSense(t *testing.T) {
}

func TestSBCFormatUnit(t *testing.T) {
}

func TestSBCUnmap(t *testing.T) {
}

func TestSBCReadWrite(t *testing.T) {
}

func TestSBCReserve(t *testing.T) {
}

func TestSBCRelease(t *testing.T) {
}

func TestSBCReadCapacity(t *testing.T) {
}

func TestSBCVerify(t *testing.T) {
}

func TestSBCReadCapacity16(t *testing.T) {
}

func TestSBCGetLbaStatus(t *testing.T) {
}

func TestSBCSyncCache(t *testing.T) {
}

func TestSBCReadDefectData10(t *testing.T) {
	cmd := &api.SCSICommand{}
	cmd.Device = &api.SCSILu{BlockShift: 9}
	cmd.InSDBBuffer = &api.SCSIDataBuffer{
		Length: 256,
		Buffer: make([]byte, 256),
	}
	// READ DEFECT DATA(10) CDB: opcode=0x37, PLIST=1, GLIST=1, format=0
	cmd.SCB = []byte{byte(api.READ_DEFECT_DATA), 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}

	result := SBCReadDefectData(0, cmd)
	if result != api.SAMStatGood {
		t.Errorf("ReadDefectData10 expected SAMStatGood, got %v", result)
	}
	if cmd.InSDBBuffer.Resid != 4 {
		t.Errorf("ReadDefectData10 expected Resid=4, got %d", cmd.InSDBBuffer.Resid)
	}
	// byte 1 should echo back PLIST|GLIST|format
	if cmd.InSDBBuffer.Buffer[1] != 0x18 {
		t.Errorf("ReadDefectData10 byte 1 expected 0x18, got 0x%02x", cmd.InSDBBuffer.Buffer[1])
	}
	// defect list length should be 0
	if cmd.InSDBBuffer.Buffer[2] != 0 || cmd.InSDBBuffer.Buffer[3] != 0 {
		t.Errorf("ReadDefectData10 defect list length should be 0")
	}
}

func TestSBCReadDefectData12(t *testing.T) {
	cmd := &api.SCSICommand{}
	cmd.Device = &api.SCSILu{BlockShift: 9}
	cmd.InSDBBuffer = &api.SCSIDataBuffer{
		Length: 256,
		Buffer: make([]byte, 256),
	}
	// READ DEFECT DATA(12) CDB: opcode=0xB7, PLIST=1, GLIST=1, format=0
	cmd.SCB = []byte{byte(api.READ_DEFECT_DATA_12), 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}

	result := SBCReadDefectData(0, cmd)
	if result != api.SAMStatGood {
		t.Errorf("ReadDefectData12 expected SAMStatGood, got %v", result)
	}
	if cmd.InSDBBuffer.Resid != 8 {
		t.Errorf("ReadDefectData12 expected Resid=8, got %d", cmd.InSDBBuffer.Resid)
	}
	// defect list length (bytes 4-7) should be 0
	for i := 4; i < 8; i++ {
		if cmd.InSDBBuffer.Buffer[i] != 0 {
			t.Errorf("ReadDefectData12 byte %d expected 0, got %d", i, cmd.InSDBBuffer.Buffer[i])
		}
	}
}

func TestSBCSanitizeInvalidServiceAction(t *testing.T) {
	cmd := &api.SCSICommand{}
	cmd.Device = &api.SCSILu{
		BlockShift: 9,
		Attrs:      api.SCSILuPhyAttribute{Online: true},
	}
	// SANITIZE with invalid service action 0x00
	cmd.SCB = []byte{byte(api.SANITIZE), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	result := SBCSanitize(0, cmd)
	if result != api.SAMStatCheckCondition {
		t.Errorf("Sanitize with invalid SA expected SAMStatCheckCondition, got %v", result)
	}
}

func TestSBCSanitizeReadonly(t *testing.T) {
	cmd := &api.SCSICommand{}
	cmd.Device = &api.SCSILu{
		BlockShift: 9,
		Attrs:      api.SCSILuPhyAttribute{Online: true, Readonly: true},
	}
	// SANITIZE OVERWRITE on readonly device
	cmd.SCB = []byte{byte(api.SANITIZE), 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	result := SBCSanitize(0, cmd)
	if result != api.SAMStatCheckCondition {
		t.Errorf("Sanitize on readonly expected SAMStatCheckCondition, got %v", result)
	}
}

func TestSBCSanitizeExitFailureMode(t *testing.T) {
	cmd := &api.SCSICommand{}
	cmd.Device = &api.SCSILu{
		BlockShift: 9,
		Attrs:      api.SCSILuPhyAttribute{Online: true},
	}
	// SANITIZE EXIT FAILURE MODE (0x1f)
	cmd.SCB = []byte{byte(api.SANITIZE), 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	result := SBCSanitize(0, cmd)
	if result != api.SAMStatGood {
		t.Errorf("Sanitize EXIT_FAILURE_MODE expected SAMStatGood, got %v", result)
	}
}

func TestNewSBCDeviceRegistersNewCommands(t *testing.T) {
	sbc := NewSBCDevice(api.TYPE_DISK)
	sbcProto := sbc.(SBCSCSIDeviceProtocol)

	// Verify new commands are registered (not SPCIllegalOp)
	newOpcodes := []struct {
		name   string
		opcode api.SCSICommandType
	}{
		{"READ_DEFECT_DATA", api.READ_DEFECT_DATA},
		{"READ_DEFECT_DATA_12", api.READ_DEFECT_DATA_12},
		{"SANITIZE", api.SANITIZE},
	}

	for _, tc := range newOpcodes {
		op := sbcProto.SCSIDeviceOps[int(tc.opcode)]
		if op.CommandPerformFunc == nil {
			t.Errorf("Command %s (0x%02x) not registered", tc.name, tc.opcode)
		}
	}

	// Verify EXTENDED_COPY and RECEIVE_COPY_RESULTS are registered (as SPCIllegalOp)
	extCopyOp := sbcProto.SCSIDeviceOps[int(api.EXTENDED_COPY)]
	if extCopyOp.CommandPerformFunc == nil {
		t.Error("EXTENDED_COPY not registered")
	}
	recvCopyOp := sbcProto.SCSIDeviceOps[int(api.RECEIVE_COPY_RESULTS)]
	if recvCopyOp.CommandPerformFunc == nil {
		t.Error("RECEIVE_COPY_RESULTS not registered")
	}
}
