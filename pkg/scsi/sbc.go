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

type SBCSCSIDeviceProtocol struct {
	BaseSCSIDeviceProtocol
}

func (sbc *SBCSCSIDeviceProtocol) InitLu(lu *SCSILu) error {
	return nil
}
func (sbc *SBCSCSIDeviceProtocol) ExitLu(lu *SCSILu) error {
	return nil
}
func (sbc *SBCSCSIDeviceProtocol) ConfigLu(lu *SCSILu) error {
	return nil
}
func (sbc *SBCSCSIDeviceProtocol) OnlineLu(lu *SCSILu) error {
	return nil
}
func (sbc *SBCSCSIDeviceProtocol) OfflineLu(lu *SCSILu) error {
	return nil
}

func NewSBCDevice() (SBCSCSIDeviceProtocol, error) {
	var sbc = SBCSCSIDeviceProtocol{
		BaseSCSIDeviceProtocol{Type: TYPE_DISK,
			SCSIDeviceOps: make([]SCSIDeviceOperation, 256)},
	}
	for i := 0; i <= 256; i++ {
		sbc.SCSIDeviceOps = append(sbc.SCSIDeviceOps, NewSCSIDeviceOperation(SPCIllegalOp, nil, 0))
	}
	sbc.SCSIDeviceOps[TEST_UNIT_READY] = NewSCSIDeviceOperation(SPCTestUnit, nil, 0)
	sbc.SCSIDeviceOps[REQUEST_SENSE] = NewSCSIDeviceOperation(SPCRequestSense, nil, 0)
	sbc.SCSIDeviceOps[FORMAT_UNIT] = NewSCSIDeviceOperation(SBCFormatUnit, nil, 0)
	sbc.SCSIDeviceOps[READ_6] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[WRITE_6] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN|PR_WE_FA|PR_WE_FN)
	sbc.SCSIDeviceOps[INQUIRY] = NewSCSIDeviceOperation(SPCInquiry, nil, 0)
	sbc.SCSIDeviceOps[MODE_SELECT] = NewSCSIDeviceOperation(SBCModeSelect, nil, PR_WE_FA|PR_EA_FA|PR_WE_FN|PR_EA_FN)
	sbc.SCSIDeviceOps[RESERVE] = NewSCSIDeviceOperation(SBCReserve, nil, 0)
	sbc.SCSIDeviceOps[RELEASE] = NewSCSIDeviceOperation(SBCRelease, nil, 0)

	sbc.SCSIDeviceOps[MODE_SENSE] = NewSCSIDeviceOperation(SBCModeSense, nil, PR_WE_FA|PR_EA_FA|PR_EA_FN|PR_WE_FN)
	sbc.SCSIDeviceOps[START_STOP] = NewSCSIDeviceOperation(SPCStartStop, nil, PR_SPECIAL)
	sbc.SCSIDeviceOps[SEND_DIAGNOSTIC] = NewSCSIDeviceOperation(SPCSendDiagnostics, nil, 0)

	sbc.SCSIDeviceOps[ALLOW_MEDIUM_REMOVAL] = NewSCSIDeviceOperation(SPCPreventAllowMediaRemoval, nil, 0)
	sbc.SCSIDeviceOps[READ_CAPACITY] = NewSCSIDeviceOperation(SBCReadCapacity, nil, 0)
	sbc.SCSIDeviceOps[READ_10] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[WRITE_10] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_WE_FA|PR_EA_FA|PR_EA_FN|PR_WE_FN)
	sbc.SCSIDeviceOps[WRITE_VERIFY] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[VERIFY_10] = NewSCSIDeviceOperation(SBCVerify, nil, PR_EA_FA|PR_EA_FN)

	sbc.SCSIDeviceOps[PRE_FETCH_10] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[SYNCHRONIZE_CACHE] = NewSCSIDeviceOperation(SBCSyncCache, nil, PR_WE_FA|PR_EA_FA|PR_WE_FN|PR_EA_FN)

	sbc.SCSIDeviceOps[WRITE_SAME] = NewSCSIDeviceOperation(SBCReadWrite, nil, 0)
	sbc.SCSIDeviceOps[UNMAP] = NewSCSIDeviceOperation(SBCUnmap, nil, 0)

	sbc.SCSIDeviceOps[MODE_SELECT_10] = NewSCSIDeviceOperation(SBCModeSelect, nil, PR_WE_FA|PR_EA_FA|PR_EA_FN|PR_WE_FN)
	sbc.SCSIDeviceOps[MODE_SENSE_10] = NewSCSIDeviceOperation(SBCModeSense, nil, PR_WE_FA|PR_WE_FN|PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[PERSISTENT_RESERVE_IN] = NewSCSIDeviceOperation(SPCServiceAction, nil, 0)
	sbc.SCSIDeviceOps[PERSISTENT_RESERVE_OUT] = NewSCSIDeviceOperation(SPCServiceAction, nil, 0)

	sbc.SCSIDeviceOps[READ_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[WRITE_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN|PR_WE_FA|PR_WE_FN)
	sbc.SCSIDeviceOps[ORWRITE_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[WRITE_VERIFY_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[VERIFY_16] = NewSCSIDeviceOperation(SBCVerify, nil, PR_EA_FA|PR_EA_FN)

	sbc.SCSIDeviceOps[PRE_FETCH_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[SYNCHRONIZE_CACHE_16] = NewSCSIDeviceOperation(SBCSyncCache, nil, PR_EA_FA|PR_EA_FN|PR_WE_FA|PR_WE_FN)
	sbc.SCSIDeviceOps[WRITE_SAME_16] = NewSCSIDeviceOperation(SBCReadWrite, nil, 0)
	sbc.SCSIDeviceOps[SERVICE_ACTION_IN] = NewSCSIDeviceOperation(SPCServiceAction, nil, 0)

	sbc.SCSIDeviceOps[REPORT_LUNS] = NewSCSIDeviceOperation(SPCReportLuns, nil, 0)
	sbc.SCSIDeviceOps[EXCHANGE_MEDIUM] = NewSCSIDeviceOperation(SPCServiceAction, nil, 0)
	sbc.SCSIDeviceOps[READ_12] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[WRITE_12] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_WE_FA|PR_EA_FA|PR_WE_FA|PR_WE_FN)
	sbc.SCSIDeviceOps[WRITE_VERIFY_12] = NewSCSIDeviceOperation(SBCReadWrite, nil, PR_EA_FA|PR_EA_FN)
	sbc.SCSIDeviceOps[VERIFY_12] = NewSCSIDeviceOperation(SBCVerify, nil, PR_EA_FA|PR_EA_FN)

	return sbc, nil
}

func SBCModeSelect(host int, cmd *SCSICommand) error {
	return nil
}

func SBCModeSense(host int, cmd *SCSICommand) error {
	return nil
}

func SBCFormatUnit(host int, cmd *SCSICommand) error {
	return nil
}

func SBCUnmap(host int, cmd *SCSICommand) error {
	return nil
}

func SBCReadWrite(host int, cmd *SCSICommand) error {
	return nil
}

func SBCReserve(host int, cmd *SCSICommand) error {
	return nil
}

func SBCRelease(host int, cmd *SCSICommand) error {
	return nil
}

func SBCReadCapacity(host int, cmd *SCSICommand) error {
	return nil
}

func SBCVerify(host int, cmd *SCSICommand) error {
	return nil
}

func SBCReadCapacity16(host int, cmd *SCSICommand) error {
	return nil
}

func SBCGetLbaStatus(host int, cmd *SCSICommand) error {
	return nil
}

func SBCServiceAction(host int, cmd *SCSICommand) error {
	return nil
}

func SBCSyncCache(host int, cmd *SCSICommand) error {
	return nil
}
