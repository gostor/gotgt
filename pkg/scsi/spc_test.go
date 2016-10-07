/*
Copyright 2016 The GoStor Authors All rights reserved.

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

// SCSI primary command processing test
package scsi

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gostor/gotgt/pkg/api"
)

// Test SPCReportLuns function
func TestSPCReportLuns(t *testing.T) {
	// make a fake REPORT_LUNS command
	cmd := new(api.SCSICommand)
	device := new(api.SCSILu)
	cmd.Device = device
	lu := new(api.SCSILu)
	target := new(api.SCSITarget)
	target.Devices = map[uint64]*api.SCSILu{0: lu}
	cmd.Target = target
	cmd.SCB = &bytes.Buffer{}
	cmd.SenseBuffer = &bytes.Buffer{}
	cmd.InSDBBuffer.Length = 16
	cmd.InSDBBuffer.Buffer = &bytes.Buffer{}
	cmd.SCB.WriteByte(byte(api.REPORT_LUNS))
	for i := 0; i < 5; i++ {
		cmd.SCB.WriteByte(0x00)
	}
	binary.Write(cmd.SCB, binary.BigEndian, uint32(16))

	if err := SPCReportLuns(0, cmd); err.Err != nil {
		t.Errorf("Expected not error, but got %v", err)
	}

	cmd.SCB = &bytes.Buffer{}
	cmd.SCB.WriteByte(byte(api.REPORT_LUNS))
	for i := 0; i < 5; i++ {
		cmd.SCB.WriteByte(0x00)
	}
	binary.Write(cmd.SCB, binary.BigEndian, uint32(10))
	if err := SPCReportLuns(0, cmd); err.Err == nil {
		t.Error("Expected error, but got nothing")
	}
}

func TestSPCStartStop(t *testing.T) {
}

func TestSPCTestUnit(t *testing.T) {
}

func TestSPCPreventAllowMediaRemoval(t *testing.T) {
}
