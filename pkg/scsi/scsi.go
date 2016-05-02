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

package scsi

import "github.com/gostor/gotgt/pkg/api"

type CommandFunc func(host int, cmd *api.SCSICommand) api.SAMStat

type SCSIServiceAction struct {
	ServiceAction      uint32
	CommandPerformFunc CommandFunc
}

type SCSIDeviceOperation struct {
	CommandPerformFunc CommandFunc
	ServiceAction      *SCSIServiceAction
	PRConflictBits     uint8
}

type BaseSCSIDeviceProtocol struct {
	Type          api.SCSIDeviceType
	SCSIDeviceOps []SCSIDeviceOperation
}

type SCSIDeviceProtocol interface {
	InitLu(lu *api.SCSILu) error
	ExitLu(lu *api.SCSILu) error
	ConfigLu(lu *api.SCSILu) error
	OnlineLu(lu *api.SCSILu) error
	OfflineLu(lu *api.SCSILu) error
}

func NewSCSIDeviceOperation(fn CommandFunc, sa *SCSIServiceAction, pr uint8) SCSIDeviceOperation {
	return SCSIDeviceOperation{
		CommandPerformFunc: fn,
		ServiceAction:      sa,
		PRConflictBits:     pr,
	}
}

func BuildSenseData(cmd *api.SCSICommand, key byte, asc SCSISubError) {
	senseBuffer := cmd.SenseBuffer
	if cmd.Device.Attrs.SenseFormat {
		// descriptor format
		// current, not deferred
		senseBuffer.WriteByte(0x72)
		senseBuffer.WriteByte(key)
		senseBuffer.WriteByte((byte(asc) >> 8) & 0xff)
		senseBuffer.WriteByte(byte(asc) & 0xff)
		cmd.SenseLength = 8
	} else {
		// fixed format
		var length uint32 = 0xa
		// current, not deferred
		senseBuffer.WriteByte(0x70)
		senseBuffer.WriteByte(0x00)
		senseBuffer.WriteByte(key)
		for i := 0; i < 4; i++ {
			senseBuffer.WriteByte(0x00)
		}
		senseBuffer.WriteByte(byte(length))
		for i := 0; i < 4; i++ {
			senseBuffer.WriteByte(0x00)
		}
		senseBuffer.WriteByte((byte(asc) >> 8) & 0xff)
		senseBuffer.WriteByte(byte(asc) & 0xff)
		cmd.SenseLength = length + 8
	}
}
