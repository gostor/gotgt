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

import "errors"

var (
	DefaultBlockShift      int = 9
	DefaultSenseBufferSize int = 252
)

type SCSIDeviceType byte

var (
	SAM_STAT_GOOD                       byte = 0x00
	SAM_STAT_CHECK_CONDITION            byte = 0x02
	SAM_STAT_CONDITION_MET              byte = 0x04
	SAM_STAT_BUSY                       byte = 0x08
	SAM_STAT_INTERMEDIATE               byte = 0x10
	SAM_STAT_INTERMEDIATE_CONDITION_MET byte = 0x14
	SAM_STAT_RESERVATION_CONFLICT       byte = 0x18
	SAM_STAT_COMMAND_TERMINATED         byte = 0x22
	SAM_STAT_TASK_SET_FULL              byte = 0x28
	SAM_STAT_ACA_ACTIVE                 byte = 0x30
	SAM_STAT_TASK_ABORTED               byte = 0x40
)

type SAMStat struct {
	Stat byte
	Err  error
}

var (
	SAMStatGood                     = SAMStat{SAM_STAT_GOOD, nil}
	SAMStatCheckCondition           = SAMStat{SAM_STAT_CHECK_CONDITION, errors.New("check condition")}
	SAMStatConditionMet             = SAMStat{SAM_STAT_CONDITION_MET, errors.New("condition met")}
	SAMStatBusy                     = SAMStat{SAM_STAT_BUSY, errors.New("busy")}
	SAMStatIntermediate             = SAMStat{SAM_STAT_INTERMEDIATE, errors.New("intermediate")}
	SAMStatIntermediateConditionMet = SAMStat{SAM_STAT_INTERMEDIATE_CONDITION_MET, errors.New("intermediate condition met")}
	SAMStatReservationConflict      = SAMStat{SAM_STAT_RESERVATION_CONFLICT, errors.New("reservation conflict")}
	SAMStatCommandTerminated        = SAMStat{SAM_STAT_COMMAND_TERMINATED, errors.New("command terminated")}
	SAMStatTaskSetFull              = SAMStat{SAM_STAT_TASK_SET_FULL, errors.New("task set full")}
	SAMStatAcaActive                = SAMStat{SAM_STAT_ACA_ACTIVE, errors.New("aca active")}
	SAMStatTaskAborted              = SAMStat{SAM_STAT_TASK_ABORTED, errors.New("task aborted")}
)

var (
	TYPE_DISK      SCSIDeviceType = 0x00
	TYPE_TAPE      SCSIDeviceType = 0x01
	TYPE_PRINTER   SCSIDeviceType = 0x02
	TYPE_PROCESSOR SCSIDeviceType = 0x03
	TYPE_WORM      SCSIDeviceType = 0x04
	TYPE_MMC       SCSIDeviceType = 0x05
	TYPE_SCANNER   SCSIDeviceType = 0x06
	TYPE_MOD       SCSIDeviceType = 0x07

	TYPE_MEDIUM_CHANGER SCSIDeviceType = 0x08
	TYPE_COMM           SCSIDeviceType = 0x09
	TYPE_RAID           SCSIDeviceType = 0x0c
	TYPE_ENCLOSURE      SCSIDeviceType = 0x0d
	TYPE_RBC            SCSIDeviceType = 0x0e
	TYPE_OSD            SCSIDeviceType = 0x11
	TYPE_NO_LUN         SCSIDeviceType = 0x7f

	TYPE_PT SCSIDeviceType = 0xff
)

type CommandFunc func(host int, cmd *SCSICommand) SAMStat

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
	Type          SCSIDeviceType
	SCSIDeviceOps []SCSIDeviceOperation
}

type SCSIDeviceProtocol interface {
	InitLu(lu *SCSILu) error
	ExitLu(lu *SCSILu) error
	ConfigLu(lu *SCSILu) error
	OnlineLu(lu *SCSILu) error
	OfflineLu(lu *SCSILu) error
}

func NewSCSIDeviceOperation(fn CommandFunc, sa *SCSIServiceAction, pr uint8) SCSIDeviceOperation {
	return SCSIDeviceOperation{
		CommandPerformFunc: fn,
		ServiceAction:      sa,
		PRConflictBits:     pr,
	}
}

func BuildSenseData(cmd *SCSICommand, key byte, asc SCSISubError) {
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
