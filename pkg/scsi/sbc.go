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
	"encoding/binary"

	"github.com/gostor/gotgt/pkg/api"
)

const (
	PR_SPECIAL = (1 << 5)
	PR_WE_FA   = (1 << 4)
	PR_EA_FA   = (1 << 3)
	PR_RR_FR   = (1 << 2)
	PR_WE_FN   = (1 << 1)
	PR_EA_FN   = (1 << 0)
)

type SBCSCSIDeviceProtocol struct {
	BaseSCSIDeviceProtocol
}

func (sbc *SBCSCSIDeviceProtocol) InitLu(lu *api.SCSILu) error {
	return nil
}
func (sbc *SBCSCSIDeviceProtocol) ExitLu(lu *api.SCSILu) error {
	return nil
}
func (sbc *SBCSCSIDeviceProtocol) ConfigLu(lu *api.SCSILu) error {
	return nil
}
func (sbc *SBCSCSIDeviceProtocol) OnlineLu(lu *api.SCSILu) error {
	return nil
}
func (sbc *SBCSCSIDeviceProtocol) OfflineLu(lu *api.SCSILu) error {
	return nil
}

func NewSBCDevice() SBCSCSIDeviceProtocol {
	var sbc = SBCSCSIDeviceProtocol{
		BaseSCSIDeviceProtocol{
			Type:          api.TYPE_DISK,
			SCSIDeviceOps: make([]SCSIDeviceOperation, 256),
		},
	}
	for i := 0; i <= 256; i++ {
		sbc.SCSIDeviceOps = append(sbc.SCSIDeviceOps, NewSCSIDeviceOperation(SPCIllegalOp, nil, 0))
	}
	sbc.SCSIDeviceOps[api.TEST_UNIT_READY] = NewSCSIDeviceOperation(SPCTestUnit, nil, 0)
	sbc.SCSIDeviceOps[api.REQUEST_SENSE] = NewSCSIDeviceOperation(SPCRequestSense, nil, 0)
	sbc.SCSIDeviceOps[api.FORMAT_UNIT] = NewSCSIDeviceOperation(SBCFormatUnit, nil, 0)
	sbc.SCSIDeviceOps[api.READ_6] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.WRITE_6] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN|PR_WE_FA|PR_WE_FN)
	sbc.SCSIDeviceOps[api.INQUIRY] = NewSCSIDeviceOperation(SPCInquiry, nil, 0)
	sbc.SCSIDeviceOps[api.MODE_SELECT] = NewSCSIDeviceOperation(SBCModeSelect, nil, PR_WE_FA|PR_EA_FA|PR_WE_FN|PR_EA_FN)
	sbc.SCSIDeviceOps[api.RESERVE] = NewSCSIDeviceOperation(SBCReserve, nil, 0)
	sbc.SCSIDeviceOps[api.RELEASE] = NewSCSIDeviceOperation(SBCRelease, nil, 0)

	sbc.SCSIDeviceOps[api.MODE_SENSE] = NewSCSIDeviceOperation(SBCModeSense, nil, PR_WE_FA|PR_EA_FA|PR_EA_FN|PR_WE_FN)
	sbc.SCSIDeviceOps[api.START_STOP] = NewSCSIDeviceOperation(SPCStartStop, nil, PR_SPECIAL)
	sbc.SCSIDeviceOps[api.SEND_DIAGNOSTIC] = NewSCSIDeviceOperation(SPCSendDiagnostics, nil, 0)

	sbc.SCSIDeviceOps[api.ALLOW_MEDIUM_REMOVAL] = NewSCSIDeviceOperation(SPCPreventAllowMediaRemoval, nil, 0)
	sbc.SCSIDeviceOps[api.READ_CAPACITY] = NewSCSIDeviceOperation(SBCReadCapacity, nil, 0)
	sbc.SCSIDeviceOps[api.READ_10] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.WRITE_10] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_WE_FA|PR_EA_FA|PR_EA_FN|PR_WE_FN)
	sbc.SCSIDeviceOps[api.WRITE_VERIFY] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.VERIFY_10] = NewSCSIDeviceOperation(SBCVerify, nil, PR_EA_FA|PR_EA_FN)

	sbc.SCSIDeviceOps[api.PRE_FETCH_10] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.SYNCHRONIZE_CACHE] = NewSCSIDeviceOperation(SBCSyncCache, nil, PR_WE_FA|PR_EA_FA|PR_WE_FN|PR_EA_FN)

	sbc.SCSIDeviceOps[api.WRITE_SAME] = NewSCSIDeviceOperation(SBCReadWrite, nil, 0)
	sbc.SCSIDeviceOps[api.UNMAP] = NewSCSIDeviceOperation(SBCUnmap, nil, 0)

	sbc.SCSIDeviceOps[api.MODE_SELECT_10] = NewSCSIDeviceOperation(SBCModeSelect, nil, PR_WE_FA|PR_EA_FA|PR_EA_FN|PR_WE_FN)
	sbc.SCSIDeviceOps[api.MODE_SENSE_10] = NewSCSIDeviceOperation(SBCModeSense, nil, PR_WE_FA|PR_WE_FN|PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.PERSISTENT_RESERVE_IN] = NewSCSIDeviceOperation(SPCServiceAction, nil, 0)
	sbc.SCSIDeviceOps[api.PERSISTENT_RESERVE_OUT] = NewSCSIDeviceOperation(SPCServiceAction, nil, 0)

	sbc.SCSIDeviceOps[api.READ_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.WRITE_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN|PR_WE_FA|PR_WE_FN)
	sbc.SCSIDeviceOps[api.ORWRITE_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.WRITE_VERIFY_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.VERIFY_16] = NewSCSIDeviceOperation(SBCVerify, nil, PR_EA_FA|PR_EA_FN)

	sbc.SCSIDeviceOps[api.PRE_FETCH_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.SYNCHRONIZE_CACHE_16] = NewSCSIDeviceOperation(SBCSyncCache, nil, PR_EA_FA|PR_EA_FN|PR_WE_FA|PR_WE_FN)
	sbc.SCSIDeviceOps[api.WRITE_SAME_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, 0)
	sbc.SCSIDeviceOps[api.SERVICE_ACTION_IN] = NewSCSIDeviceOperation(SPCServiceAction, nil, 0)

	sbc.SCSIDeviceOps[api.REPORT_LUNS] = NewSCSIDeviceOperation(SPCReportLuns, nil, 0)
	sbc.SCSIDeviceOps[api.EXCHANGE_MEDIUM] = NewSCSIDeviceOperation(SPCServiceAction, nil, 0)
	sbc.SCSIDeviceOps[api.READ_12] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.WRITE_12] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_WE_FA|PR_EA_FA|PR_WE_FA|PR_WE_FN)
	sbc.SCSIDeviceOps[api.WRITE_VERIFY_12] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[api.VERIFY_12] = NewSCSIDeviceOperation(SBCVerify, nil, PR_EA_FA|PR_EA_FN)

	return sbc
}

func SBCModeSelect(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SBCModeSense(host int, cmd *api.SCSICommand) api.SAMStat {
	// DPOFUA = 0x10
	var deviceSpecific uint8 = 0x10

	if err := SPCModeSense(host, cmd); err.Err != nil {
		return err
	}

	// If this is a read-only lun, we must set the write protect bit
	if cmd.Device.Attrs.Readonly || cmd.Device.Attrs.SWP {
		deviceSpecific |= 0x80
	}

	data := cmd.InSDBBuffer.Buffer
	data.Next(2)

	if cmd.SCB.Bytes()[0] == 0x1a {
		data.WriteByte(deviceSpecific)
	} else {
		data.Next(1)
		data.WriteByte(deviceSpecific)
	}

	return api.SAMStatGood
}

// The FORMAT UNIT command requests that the device server format the medium into application client
// accessible logical blocks as specified in the number of blocks and block length values received
// in the last mode parameter block descriptor in a MODE SELECT command (see SPC-3).  In addition,
// the device server may certify the medium and create control structures for the management of the medium and defects.
// The degree that the medium is altered by this command is vendor-specific.
func SBCFormatUnit(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		key = ILLEGAL_REQUEST
		asc = ASC_INVALID_FIELD_IN_CDB
	)

	if err := deviceReserve(cmd); err != nil {
		return api.SAMStatReservationConflict
	}

	if !cmd.Device.Attrs.Online {
		key = NOT_READY
		asc = ASC_MEDIUM_NOT_PRESENT
		goto sense
	}

	if cmd.Device.Attrs.Readonly || cmd.Device.Attrs.SWP {
		key = DATA_PROTECT
		asc = ASC_WRITE_PROTECT
		goto sense
	}

	if cmd.SCB.Bytes()[1]&0x80 != 0 {
		// we dont support format protection information
		goto sense
	}
	if cmd.SCB.Bytes()[1]&0x10 != 0 {
		// we dont support format data
		goto sense
	}
	if cmd.SCB.Bytes()[1]&0x07 != 0 {
		// defect list format must be 0
		goto sense
	}

	return api.SAMStatGood
sense:
	BuildSenseData(cmd, key, asc)
	return api.SAMStatCheckCondition
}

func SBCUnmap(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SBCReadWrite(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SBCReserve(host int, cmd *api.SCSICommand) api.SAMStat {
	if err := deviceReserve(cmd); err != nil {
		return api.SAMStatReservationConflict
	}
	return api.SAMStatGood
}

func SBCRelease(host int, cmd *api.SCSICommand) api.SAMStat {
	if err := deviceRelease(cmd.Target.TID, cmd.CommandITNID, cmd.Device.Lun, false); err != nil {
		return api.SAMStatReservationConflict
	}

	return api.SAMStatGood
}

// The READ CAPACITY (10) command requests that the device server transfer 8 bytes of parameter data
// describing the capacity and medium format of the direct-access block device to the data-in buffer.
// This command may be processed as if it has a HEAD OF QUEUE task attribute.  If the logical unit supports
// protection information, the application client should use the READ CAPACITY (16) command instead of
// the READ CAPACITY (10) command.
func SBCReadCapacity(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		scb    = cmd.SCB.Bytes()
		key    = ILLEGAL_REQUEST
		asc    = ASC_LUN_NOT_SUPPORTED
		data   = cmd.InSDBBuffer.Buffer
		bshift = cmd.Device.BlockShift
		size   = cmd.Device.Size >> bshift
	)

	if cmd.Device.Attrs.Removable && !cmd.Device.Attrs.Online {
		key = NOT_READY
		asc = ASC_MEDIUM_NOT_PRESENT
		goto sense
	}

	if (scb[8]&0x1 == 0) && (scb[2]|scb[3]|scb[4]|scb[5]) != 0 {
		asc = ASC_INVALID_FIELD_IN_CDB
		goto sense
	}

	if cmd.InSDBBuffer.Length < 8 {
		goto overflow
	}

	// data[0] = (size >> 32) ? __cpu_to_be32(0xffffffff) : __cpu_to_be32(size - 1);
	if size>>32 != 0 {
		binary.Write(data, binary.BigEndian, uint32(0xffffffff))
	} else {
		binary.Write(data, binary.BigEndian, uint32(size-1))
	}

	// data[1] = __cpu_to_be32(1U << bshift);
	binary.Write(data, binary.BigEndian, uint32(1<<bshift))
overflow:
	cmd.InSDBBuffer.Resid = 8
	return api.SAMStatGood
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, key, asc)
	return api.SAMStatCheckCondition
}

// The VERIFY (10) command requests that the device server verify the specified logical block(s) on the medium.
func SBCVerify(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		key = ILLEGAL_REQUEST
		asc = ASC_INVALID_FIELD_IN_CDB
	)
	if cmd.Device.Attrs.Removable && !cmd.Device.Attrs.Online {
		key = NOT_READY
		asc = ASC_MEDIUM_NOT_PRESENT
		goto sense
	}

	if cmd.SCB.Bytes()[1]&0xe0 != 0 {
		// We only support protection information type 0
		key = ILLEGAL_REQUEST
		asc = ASC_INVALID_FIELD_IN_CDB
		goto sense
	}

	if cmd.SCB.Bytes()[1]&0x02 == 0 {
		// no data compare with the media
		return api.SAMStatGood
	}
	// TODO
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, key, asc)
	return api.SAMStatCheckCondition
}

func SBCReadCapacity16(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SBCGetLbaStatus(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SBCServiceAction(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

// The SYNCHRONIZE CACHE (10) command requests that the device server ensure that
// the specified logical blocks have their most recent data values recorded in
// non-volatile cache and/or on the medium, based on the SYNC_NV bit.
func SBCSyncCache(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}
