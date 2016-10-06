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

// SCSI primary command processing
package scsi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/golang/glog"
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
	var (
		buf          = &bytes.Buffer{}
		data  []byte = []byte{}
		b     byte   = 0x75
		scb   []byte = cmd.SCB.Bytes()
		pcode byte   = scb[2]
		evpd  bool   = false
	)
	if scb[1]&0x01 > 0 {
		evpd = true
	}
	if reflect.DeepEqual(util.MarshalUint64(cmd.Device.Lun)[0:7], cmd.Lun[0:7]) {
		b = (uint8(0) & 0x7) << 5
		b |= uint8(0) & 0x1f
	}
	glog.V(2).Infof("%v, %v", cmd.Device.Lun, *(*uint64)(unsafe.Pointer(&cmd.Lun)))
	if cmd.Device.Lun != *(*uint64)(unsafe.Pointer(&cmd.Lun)) {
		goto sense
	}
	if evpd {
		if pcode == 0x0 {
			buf.WriteByte(b)
			b = 0
			buf.WriteByte(b)
			buf.WriteByte(b)
			buf.WriteByte(b)
			buf.WriteByte(b)
			buf.WriteByte(b)
		} else if pcode == 0xb0 {
			buf.WriteByte(b)
			buf.WriteByte(0xb0)
			buf.WriteByte(0x00)
			buf.WriteByte(0x3c)
			buf.WriteByte(0x00)
			buf.WriteByte(0x80)

			for i := 0; i < 58; i++ {
				buf.WriteByte(0x00)
			}
		} else {
			buf.WriteByte(b)
			buf.WriteByte(0xb0)
			buf.WriteByte(0x00)
			buf.WriteByte(0x00)
			buf.WriteByte(0x00)
		}
	} else {
		buf.WriteByte(b)
		b = 0
		buf.WriteByte(b)
		buf.WriteByte(byte(1))
		b = 0x02
		buf.WriteByte(b)
		buf.WriteByte(0x00)
		// byte 5
		b = 0
		b |= byte(1) << 4 & 0x30
		buf.WriteByte(b)
		// byte 6
		b = 0
		buf.WriteByte(b)
		buf.WriteByte(0x02)
		buf.Write([]byte{'1', '1', 'c', 'a', 'n', 's'})
		buf.WriteByte(0x00)
		buf.WriteByte(0x00)
		buf.Write([]byte{'c', 'o', 'f', 'f', 'e', 'e'})
		for i := 0; i < 10; i++ {
			buf.WriteByte(0x00)
		}
		buf.Write([]byte{'1', '.', '0'})
		buf.WriteByte(0x00)
	}
	data = buf.Bytes()
	data[4] = byte(len(data) - 4)
	cmd.InSDBBuffer.Buffer = bytes.NewBuffer(data)
	return api.SAMStatGood
sense:
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCReportLuns(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		remainLength     uint32
		actualLength     uint32 = 8
		availLength      uint32 = 0
		allocationLength uint32
		buf              *bytes.Buffer = &bytes.Buffer{}
		scb              *bytes.Buffer = cmd.SCB
	)
	// Get Allocation Length
	allocationLength = util.GetUnalignedUint32(scb.Bytes()[6:10])
	if allocationLength < 16 {
		glog.Warningf("goto sense, allocationLength < 16")
		goto sense
	}
	remainLength = allocationLength - 8
	availLength = 8 * uint32(len(cmd.Target.Devices))
	buf.Write(util.MarshalUint32(availLength))
	cmd.InSDBBuffer.Resid = int32(actualLength)
	// Skip through to byte 8, Reserved
	for i := 0; i < 4; i++ {
		buf.WriteByte(0x00)
	}

	for lunumber, lu := range cmd.Target.Devices {
		glog.V(2).Infof("LUN: ", lunumber)
		if remainLength > 0 {
			lun := lu.Lun
			if lun > 0xff {
				lun = 0x1 << 30
			} else {
				lun = 0
			}
			lun = (0x3fff & lun) << 16
			lun = uint64(lun << 32)
			buf.Write(util.MarshalUint64(lun))
			remainLength -= 8
		}
	}
	cmd.InSDBBuffer.Buffer = buf
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
	/*
		if err := deviceReserve(cmd); err != nil {
			return api.SAMStatReservationConflict
		}
	*/
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
	var (
		scb            = cmd.SCB.Bytes()
		mode6          = (scb[0] == 0x1a)
		dbd            = scb[1] & 0x8 /* Disable Block Descriptors */
		pcode          = scb[2] & 0x3f
		pctrl          = (scb[2] & 0xc0) >> 6
		subpcode       = scb[3]
		blkDesctionLen = 0
		key            = ILLEGAL_REQUEST
		asc            = ASC_INVALID_FIELD_IN_CDB
	)
	if dbd == 0 {
		blkDesctionLen = 8
	}
	if pctrl == 3 {
		asc = ASC_SAVING_PARMS_UNSUP
		goto sense
	}
	_ = dbd
	_ = pcode
	_ = subpcode
	_ = mode6
	_ = blkDesctionLen
	return api.SAMStatGood
sense:
	BuildSenseData(cmd, key, asc)
	return api.SAMStatCheckCondition
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

func getSCSICmdSize(opcode api.SCSICommandType) byte {
	var scsi_command_size = []byte{6, 10, 10, 12, 16, 12, 10, 10}

	return scsi_command_size[(byte(opcode)>>5)&7]
}

func reportOpcodesAll(cmd *api.SCSICommand, rctd int) error {
	var (
		data = []byte{0x00, 0x00, 0x00, 0x00}
	)
	for _, i := range []api.SCSICommandType{api.TEST_UNIT_READY, api.WRITE_6, api.INQUIRY, api.READ_CAPACITY, api.WRITE_10, api.WRITE_16, api.REPORT_LUNS, api.WRITE_12} {
		data = append(data, byte(i))
		// reserved
		data = append(data, 0x00)
		// service action
		data = append(data, 0x00)
		data = append(data, 0x00)
		// reserved
		data = append(data, 0x00)
		// flags : no service action, possibly timeout desc
		if rctd != 0 {
			data = append(data, 0x02)
		} else {
			data = append(data, 0x00)
		}
		// cdb length
		length := getSCSICmdSize(i)
		data = append(data, (length>>8)&0xff)
		data = append(data, length&0xff)
		// timeout descriptor
		if rctd != 0 {
			// length == 0x0a
			data[1] = 0x0a
			for n := 0; n < 12; n++ {
				data = append(data, 0x00)
			}
		}
	}
	buf := util.MarshalUint32(uint32(len(data) - 4))
	buf = append(buf, data[4:]...)
	cmd.InSDBBuffer.Buffer = bytes.NewBuffer(buf)
	return nil
}

func reportOpcodeOne(cmd *api.SCSICommand, rctd int, opcode byte, rsa uint16, serviceAction bool) error {
	return nil
}

// This is useful for the various commands using the SERVICE ACTION format.
func SPCServiceAction(host int, cmd *api.SCSICommand) api.SAMStat {
	// TODO
	scb := cmd.SCB.Bytes()
	reporting_options := scb[2] & 0x07
	opcode := scb[3]
	rctd := int(scb[2] & 0x80)
	rsa := util.GetUnalignedUint16(scb[4:])
	switch reporting_options {
	case 0x00: /* report all */
		glog.V(3).Infof("Service Action: report all")
		err := reportOpcodesAll(cmd, rctd)
		if err != nil {
			glog.Error(err)
			goto sense
		}
	case 0x01: /* report one no service action*/
		glog.V(3).Infof("Service Action: report one no service action")
		err := reportOpcodeOne(cmd, rctd, opcode, rsa, false)
		if err != nil {
			glog.Error(err)
			goto sense
		}
	case 0x02: /* report one service action */
		glog.V(3).Infof("Service Action: report one service action")
		err := reportOpcodeOne(cmd, rctd, opcode, rsa, true)
		if err != nil {
			glog.Error(err)
			goto sense
		}
	default:
		goto sense
	}
	return api.SAMStatGood

sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
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
		data             = &bytes.Buffer{}
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
	if cmd.SenseBuffer != nil {
		data.Write(cmd.SenseBuffer.Bytes()[0:actualLength])
	}
	cmd.InSDBBuffer.Resid = int32(actualLength)
	cmd.InSDBBuffer.Buffer = data

	// reset sense buffer in cmnd
	cmd.SenseBuffer = &bytes.Buffer{}
	cmd.SenseLength = 0

	return api.SAMStatGood
}
