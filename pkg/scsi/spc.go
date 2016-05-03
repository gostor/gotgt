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

// SCSI primary command processing
package scsi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/util"
)

/*
 * Protocol Identifier Values
 *
 * 0 Fibre Channel (FCP-2)
 * 1 Parallel SCSI (SPI-5)
 * 2 SSA (SSA-S3P)
 * 3 IEEE 1394 (SBP-3)
 * 4 SCSI Remote Direct Memory Access (SRP)
 * 5 iSCSI
 * 6 SAS Serial SCSI Protocol (SAS)
 * 7 Automation/Drive Interface (ADT)
 * 8 AT Attachment Interface (ATA/ATAPI-7)
 */

const (
	PIV_FCP = iota
	PIV_SPI
	PIV_S3P
	PIV_SBP
	PIV_SRP
	PIV_ISCSI
	PIV_SAS
	PIV_ADT
	PIV_ATA
)

/*
 * Code Set
 *
 *  1 - Designator fild contains binary values
 *  2 - Designator field contains ASCII printable chars
 *  3 - Designaotor field contains UTF-8
 */
type CodeSet int

var (
	INQ_CODE_BIN   CodeSet = 1
	INQ_CODE_ASCII CodeSet = 2
	INQ_CODE_UTF8  CodeSet = 3
)

/*
 * Association field
 *
 * 00b - Associated with Logical Unit
 * 01b - Associated with target port
 * 10b - Associated with SCSI Target device
 * 11b - Reserved
 */
type AssociationField int

var (
	ASS_LU       AssociationField = 0
	ASS_TGT_PORT AssociationField = 0x10
	ASS_TGT_DEV  AssociationField = 0x20
)

/*
 * Designator type - SPC-4 Reference
 *
 * 0 - Vendor specific - 7.6.3.3
 * 1 - T10 vendor ID - 7.6.3.4
 * 2 - EUI-64 - 7.6.3.5
 * 3 - NAA - 7.6.3.6
 * 4 - Relative Target port identifier - 7.6.3.7
 * 5 - Target Port group - 7.6.3.8
 * 6 - Logical Unit group - 7.6.3.9
 * 7 - MD5 logical unit identifier - 7.6.3.10
 * 8 - SCSI name string - 7.6.3.11
 */

const (
	DESG_VENDOR = iota
	DESG_T10
	DESG_EUI64
	DESG_NAA
	DESG_REL_TGT_PORT
	DESG_TGT_PORT_GRP
	DESG_LU_GRP
	DESG_MD5
	DESG_SCSI
)

func SPCIllegalOp(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SPCLuOffline(lu *api.SCSILu) error {
	lu.Attrs.Online = true
	return nil
}

func SPCLuOnline(lu *api.SCSILu) error {
	if luPreventRemoval(lu) {
		return fmt.Errorf("lu(%s) prevent removal", lu.Lun)
	}

	lu.Attrs.Online = false
	return nil
}

func SPCInquiry(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SPCReportLuns(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		remainLength     uint32
		actualLength     uint32 = 8
		availLength      uint32 = 0
		allocationLength uint32
		data             *bytes.Buffer
		scb              *bytes.Buffer = cmd.SCB
	)
	// Get Allocation Length
	allocationLength = util.GetUnalignedUint32(scb.Bytes()[6:10])
	if allocationLength < 16 {
		goto sense
	}
	if cmd.InSDBBuffer.Length < allocationLength {
		goto sense
	}
	data = cmd.InSDBBuffer.Buffer
	remainLength = allocationLength - 8
	availLength = 8 * uint32(len(cmd.Target.Devices))
	binary.Write(data, binary.BigEndian, availLength)
	cmd.InSDBBuffer.Resid = int32(actualLength)
	// Skip through to byte 8, Reserved
	for i := 0; i < 4; i++ {
		data.WriteByte(0x00)
	}

	for _, lu := range cmd.Target.Devices {
		if remainLength > 0 {
			lun := lu.Lun
			if lun > 0xff {
				lun = 0x1 << 30
			} else {
				lun = 0
			}
			lun = (0x3fff & lun) << 16
			lun = uint64(lun << 32)
			binary.Write(data, binary.BigEndian, lun)
			remainLength -= 8
		}
	}
	return api.SAMStatGood
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCStartStop(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		pwrcnd, loej, start byte
	)
	if err := deviceReserve(cmd); err != nil {
		return api.SAMStatReservationConflict
	}

	cmd.InSDBBuffer.Resid = 0
	scb := cmd.SCB.Bytes()
	pwrcnd = scb[4] & 0xf0
	if pwrcnd != 0 {
		return api.SAMStatGood
	}

	loej = scb[4] & 0x02
	start = scb[4] & 0x01

	if loej != 0 && start == 0 && cmd.Device.Attrs.Removable {
		if luPreventRemoval(cmd.Device) {
			if cmd.Device.Attrs.Online {
				//  online == media is present
				BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_MEDIUM_REMOVAL_PREVENTED)
			} else {
				// !online == media is not present
				BuildSenseData(cmd, NOT_READY, ASC_MEDIUM_REMOVAL_PREVENTED)
			}
			return api.SAMStatCheckCondition
		}
		SPCLuOffline(cmd.Device)
	}
	if loej != 0 && start != 0 && cmd.Device.Attrs.Removable {
		SPCLuOnline(cmd.Device)
	}

	return api.SAMStatGood
}

func SPCTestUnit(host int, cmd *api.SCSICommand) api.SAMStat {
	if err := deviceReserve(cmd); err != nil {
		return api.SAMStatReservationConflict
	}
	if cmd.Device.Attrs.Online {
		return api.SAMStatGood
	}
	if cmd.Device.Attrs.Removable {
		BuildSenseData(cmd, NOT_READY, ASC_MEDIUM_NOT_PRESENT)
	} else {
		BuildSenseData(cmd, NOT_READY, ASC_BECOMING_READY)
	}

	return api.SAMStatCheckCondition
}

func SPCPreventAllowMediaRemoval(host int, cmd *api.SCSICommand) api.SAMStat {
	if err := deviceReserve(cmd); err != nil {
		return api.SAMStatReservationConflict
	}
	// PREVENT_MASK = 0x03
	cmd.ITNexusLuInfo.Prevent = int(cmd.SCB.Bytes()[4] & 0x03)
	return api.SAMStatGood
}

// SPCModeSense Implement SCSI op MODE SENSE(6) and MODE SENSE(10)
//  Reference : SPC4r11
//  6.11 - MODE SENSE(6)
//  6.12 - MODE SENSE(10)
func SPCModeSense(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SPCSendDiagnostics(host int, cmd *api.SCSICommand) api.SAMStat {
	// we only support SELF-TEST==1
	if cmd.SCB.Bytes()[1]&0x04 == 0 {
		goto sense
	}

	return api.SAMStatGood
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

// This is useful for the various commands using the SERVICE ACTION format.
func SPCServiceAction(host int, cmd *api.SCSICommand) api.SAMStat {
	// TODO
	return api.SAMStatGood
}

func SPCPRReadKeys(host int, cmd *api.SCSICommand) api.SAMStat {
	allocationLength := util.GetUnalignedUint32(cmd.SCB.Bytes()[7:9])
	if allocationLength < 8 {
		goto sense
	}
	if cmd.InSDBBuffer.Length < allocationLength {
		goto sense
	}
	// TODO
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCPRReadReservation(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SPCPRReportCapabilities(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		buf          []byte        = make([]byte, 8)
		availLength  uint32        = 8
		actualLength uint32        = 0
		data         *bytes.Buffer = cmd.InSDBBuffer.Buffer
	)
	allocationLength := util.GetUnalignedUint32(cmd.SCB.Bytes()[7:9])
	if allocationLength < 8 {
		goto sense
	}
	if cmd.InSDBBuffer.Length < allocationLength {
		goto sense
	}
	binary.BigEndian.PutUint16(buf[0:2], uint16(8))
	// Persistent Reservation Type Mask format
	// Type Mask Valid (TMV)
	buf[3] |= 0x80
	// PR_TYPE_EXCLUSIVE_ACCESS_ALLREG
	buf[4] |= 0x80
	// PR_TYPE_EXCLUSIVE_ACCESS_REGONLY
	buf[4] |= 0x40
	// PR_TYPE_WRITE_EXCLUSIVE_REGONLY
	buf[4] |= 0x20
	// PR_TYPE_EXCLUSIVE_ACCESS
	buf[4] |= 0x08
	// PR_TYPE_WRITE_EXCLUSIVE
	buf[4] |= 0x02
	// PR_TYPE_EXCLUSIVE_ACCESS_ALLREG
	buf[5] |= 0x01

	if err := binary.Write(data, binary.BigEndian, buf); err != nil {
		goto sense
	} else {
		actualLength = availLength
	}
	cmd.InSDBBuffer.Resid = int32(actualLength)
	return api.SAMStatGood
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCPRRegister(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SPCPRReserve(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SPCPRRelease(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SPCPRClear(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SPCPRPreempt(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SPCPRRegisterAndMove(host int, cmd *api.SCSICommand) api.SAMStat {
	return api.SAMStatGood
}

func SPCRequestSense(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		allocationLength uint32
		actualLength     uint32
	)

	allocationLength = util.GetUnalignedUint32(cmd.SCB.Bytes()[4:8])
	if allocationLength > cmd.InSDBBuffer.Length {
		allocationLength = cmd.InSDBBuffer.Length
	}
	BuildSenseData(cmd, NO_SENSE, NO_ADDITIONAL_SENSE)
	if cmd.SenseLength < allocationLength {
		actualLength = cmd.SenseLength
	} else {
		actualLength = allocationLength
	}
	binary.Write(cmd.InSDBBuffer.Buffer, binary.BigEndian, cmd.SenseBuffer.Bytes()[0:actualLength])
	cmd.InSDBBuffer.Resid = int32(actualLength)

	// reset sense buffer in cmnd
	cmd.SenseBuffer = &bytes.Buffer{}
	cmd.SenseLength = 0

	return api.SAMStatGood
}
