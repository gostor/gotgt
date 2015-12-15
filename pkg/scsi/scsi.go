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

var (
	DefaultBlockShift      int = 9
	DefaultSenseBufferSize int = 252
)

type SAMStat byte
type SCSIDeviceType byte

var (
	SAM_STAT_GOOD                       SAMStat = 0x00
	SAM_STAT_CHECK_CONDITION            SAMStat = 0x02
	SAM_STAT_CONDITION_MET              SAMStat = 0x04
	SAM_STAT_BUSY                       SAMStat = 0x08
	SAM_STAT_INTERMEDIATE               SAMStat = 0x10
	SAM_STAT_INTERMEDIATE_CONDITION_MET SAMStat = 0x14
	SAM_STAT_RESERVATION_CONFLICT       SAMStat = 0x18
	SAM_STAT_COMMAND_TERMINATED         SAMStat = 0x22
	SAM_STAT_TASK_SET_FULL              SAMStat = 0x28
	SAM_STAT_ACA_ACTIVE                 SAMStat = 0x30
	SAM_STAT_TASK_ABORTED               SAMStat = 0x40
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

type CommandFunc func(host int, cmd *SCSICommand) error

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
