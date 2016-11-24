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

	"github.com/golang/glog"
	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/util"
	"github.com/satori/go.uuid"
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
	PIV_FCP   = byte(0x00)
	PIV_SPI   = byte(0x01)
	PIV_S3P   = byte(0x02)
	PIV_SBP   = byte(0x03)
	PIV_SRP   = byte(0x04)
	PIV_ISCSI = byte(0x05)
	PIV_SAS   = byte(0x06)
	PIV_ADT   = byte(0x07)
	PIV_ATA   = byte(0x08)
	PIV_USB   = byte(0x09)
	PIV_SOP   = byte(0x0A)
)

const (
	VERSION_NOT_CLAIM         = byte(0x00)
	VERSION_WITHDRAW_STANDARD = byte(0x03)
	VERSION_WITHDRAW_SPC2     = byte(0x04)
	VERSION_WITHDRAW_SPC3     = byte(0x05)
)

/*
 * Code Set
 *
 *  1 - Designator fild contains binary values
 *  2 - Designator field contains ASCII printable chars
 *  3 - Designaotor field contains UTF-8
 */

const (
	INQ_CODE_BIN   = byte(1)
	INQ_CODE_ASCII = byte(2)
	INQ_CODE_UTF8  = byte(3)
)

/*
 * Association field
 *
 * 00b - Associated with Logical Unit
 * 01b - Associated with target port
 * 10b - Associated with SCSI Target device
 * 11b - Reserved
 */

const (
	ASS_LU       = byte(0x00)
	ASS_TGT_PORT = byte(0x01)
	ASS_TGT_DEV  = byte(0x02)
)

/*
 * Table 177 — PERIPHERAL QUALIFIER field
 * Qualifier Description
 * 000b - A peripheral device having the indicated peripheral
 * 	device type is connected to this logical unit. If the device server is
 * 	unable to determine whether or not a peripheral device is connected,
 * 	then the device server also shall use this peripheral qualifier.
 * 	This peripheral qualifier does not indicate that the peripheral
 * 	device connected to the logical unit is ready for access.
 * 001b - A peripheral device having the indicated peripheral device type
 * 	is not connected to this logical unit. However, the device server is capable of
 *	supporting the indicated peripheral device type on this logical unit.
 * 010b - Reserved
 * 011b - The device server is not capable of supporting a
 * 	peripheral device on this logical unit. For this peripheral
 *	qualifier the peripheral device type shall be set to 1Fh. All other peripheral
 * device type values are reserved for this peripheral qualifier.
 * 100b to 111b Vendor specific
 */

const (
	PQ_DEVICE_CONNECTED   = byte(0x00 << 5)
	PQ_DEVICE_NOT_CONNECT = byte(0x01 << 5)
	PQ_RESERVED           = byte(0x02 << 5)
	PQ_NOT_SUPPORT        = byte(0x03 << 5)
)

const (
	INQUIRY_SCCS          = byte(0x80)
	INQUIRY_AAC           = byte(0x40)
	INQUIRY_TPGS_NO       = byte(0x00)
	INQUIRY_TPGS_IMPLICIT = byte(0x10)
	INQUIRY_TPGS_EXPLICIT = byte(0x20)
	INQUIRY_TPGS_BOTH     = byte(0x30)
	INQUIRY_3PC           = byte(0x08)
	INQUIRY_Reserved      = byte(0x06)
	INQUIRY_PROTECT       = byte(0x01)

	INQUIRY_NORM_ACA        = byte(0x20)
	INQUIRY_HISUP           = byte(0x10)
	INQUIRY_STANDARD_FORMAT = byte(0x02)

	INQUIRY_ENCSERV = byte(0x40)
	INQUIRY_VS0     = byte(0x20)
	INQUIRY_MULTIP  = byte(0x10)
	INQUIRY_ADDR16  = byte(0x01)

	INQUIRY_WBUS16 = byte(0x20)
	INQUIRY_SYNC   = byte(0x10)
	INQUIRY_CMDQUE = byte(0x02)
	INQUIRY_VS1    = byte(0x01)

	INQUIRY_QAS = byte(0x02)
	INQUIRY_IUS = byte(0x01)
)

const (
	ADDRESS_METHOD_PERIPHERAL_DEVICE     = byte(0x00)
	ADDRESS_METHOD_FLAT_SPACE            = byte(0x01)
	ADDRESS_METHOD_LOGICAL_UNIT          = byte(0x02)
	ADDRESS_METHOD_EXTENDED_LOGICAL_UNIT = byte(0x03)
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

const (
	NAA_IEEE_EXTD      = byte(0x2)
	NAA_LOCAL          = byte(0x3)
	NAA_IEEE_REGD      = byte(0x5)
	NAA_IEEE_REGD_EXTD = byte(0x6)
)

const (
	SCSI_VendorID  = "GOSTOR"
	SCSI_ProductID = "GOTGT"
)

func SPCIllegalOp(host int, cmd *api.SCSICommand) api.SAMStat {
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCLuOffline(lu *api.SCSILu) error {
	lu.Attrs.Online = true
	return nil
}

func SPCLuOnline(lu *api.SCSILu) error {
	if luPreventRemoval(lu) {
		return fmt.Errorf("lu prevent removal")
	}

	lu.Attrs.Online = false
	return nil
}

func InquiryPage0x00(host int, cmd *api.SCSICommand) (*bytes.Buffer, uint16) {
	var (
		buf               = &bytes.Buffer{}
		descBuf           = &bytes.Buffer{}
		data       []byte = []byte{}
		pageLength uint16 = 0
	)

	descBuf.WriteByte(0x00)
	descBuf.WriteByte(0x80)
	descBuf.WriteByte(0x83)
	/*
		TODO:
			descBuf.WriteByte(0x86)
			descBuf.WriteByte(0xB0)
			descBuf.WriteByte(0xB2)
	*/

	data = descBuf.Bytes()
	pageLength = uint16(len(data))

	//byte 0
	if cmd.Device.Attrs.Online {
		buf.WriteByte(PQ_DEVICE_CONNECTED | byte(cmd.Device.Attrs.DeviceType))
	} else {
		buf.WriteByte(PQ_DEVICE_NOT_CONNECT | byte(cmd.Device.Attrs.DeviceType))
	}
	//byte 1
	//PAGE CODE
	buf.WriteByte(0x00)
	//PAGE LENGTH
	binary.Write(buf, binary.BigEndian, pageLength)
	buf.Write(data)
	return buf, pageLength
}

func InquiryPage0x80(host int, cmd *api.SCSICommand) (*bytes.Buffer, uint16) {
	var (
		buf               = &bytes.Buffer{}
		descBuf           = &bytes.Buffer{}
		data       []byte = []byte{}
		pageLength uint16 = 0
	)

	descBuf.WriteByte(0x20)
	descBuf.WriteByte(0x20)
	descBuf.WriteByte(0x20)
	descBuf.WriteByte(0x20)

	data = descBuf.Bytes()
	pageLength = uint16(len(data))

	//byte 0
	if cmd.Device.Attrs.Online {
		buf.WriteByte(PQ_DEVICE_CONNECTED | byte(cmd.Device.Attrs.DeviceType))
	} else {
		buf.WriteByte(PQ_DEVICE_NOT_CONNECT | byte(cmd.Device.Attrs.DeviceType))
	}
	//byte 1
	//PAGE CODE
	buf.WriteByte(0x80)
	//PAGE LENGTH
	binary.Write(buf, binary.BigEndian, pageLength)
	buf.Write(data)
	return buf, pageLength
}

func InquiryPage0x83(host int, cmd *api.SCSICommand) (*bytes.Buffer, uint16) {
	var (
		buf               = &bytes.Buffer{}
		descBuf           = &bytes.Buffer{}
		data       []byte = []byte{}
		portName   []byte
		pageLength uint16              = 0
		portID     uint16              = cmd.RelTargetPortID
		portGroup  uint16              = FindTargetGroup(cmd.Target, portID)
		targetPort *api.SCSITargetPort = FindTargetPort(cmd.Target, portID)
	)

	//DESCRIPTOR 1 TARGET NAME
	descBuf.WriteByte((PIV_ISCSI << 4) | INQ_CODE_ASCII)
	descBuf.WriteByte(0x80 | (ASS_TGT_PORT << 4) | DESG_VENDOR)
	descBuf.WriteByte(0x00)
	//length
	descBuf.WriteByte(byte(len([]byte(cmd.Target.Name))))
	//target name
	descBuf.Write([]byte(cmd.Target.Name))

	//DESCRIPTOR 2 NNA Locally
	descBuf.WriteByte((PIV_ISCSI << 4) | INQ_CODE_BIN)
	descBuf.WriteByte(0x80 | (ASS_LU << 4) | DESG_NAA)
	descBuf.WriteByte(0x00)
	//length
	descBuf.WriteByte(0x08)
	//NNA
	binary.Write(descBuf, binary.BigEndian, (cmd.Device.UUID | (uint64(NAA_LOCAL) << 60)))

	//TODO: Target Port Group(0x05), Relative Target port identifier(0x04)

	//DESCRIPTOR 3 TPG
	descBuf.WriteByte((PIV_ISCSI << 4) | INQ_CODE_BIN)
	descBuf.WriteByte(0x80 | (ASS_TGT_PORT << 4) | DESG_TGT_PORT_GRP)
	descBuf.WriteByte(0x00)
	//length
	descBuf.WriteByte(0x04)
	//TPG
	descBuf.WriteByte(0x00)
	descBuf.WriteByte(0x00)
	binary.Write(descBuf, binary.BigEndian, portGroup)

	//DESCRIPTOR 4 Relative Target Port ID
	descBuf.WriteByte((PIV_ISCSI << 4) | INQ_CODE_BIN)
	descBuf.WriteByte(0x80 | (ASS_TGT_PORT << 4) | DESG_REL_TGT_PORT)
	descBuf.WriteByte(0x00)
	//length
	descBuf.WriteByte(0x04)
	//RTPGI
	descBuf.WriteByte(0x00)
	descBuf.WriteByte(0x00)
	binary.Write(descBuf, binary.BigEndian, portID)

	//DESCRIPTOR 5 SCSI Name,Port
	portName = util.StringToByte(targetPort.TargetPortName, 4, 256)
	descBuf.WriteByte((PIV_ISCSI << 4) | INQ_CODE_UTF8)
	descBuf.WriteByte(0x80 | (ASS_TGT_PORT << 4) | DESG_SCSI)
	descBuf.WriteByte(0x00)
	//length
	descBuf.WriteByte(byte(len(portName)))
	//RTPGI
	descBuf.Write(portName)

	data = descBuf.Bytes()
	pageLength = uint16(len(data))

	//byte 0
	if cmd.Device.Attrs.Online {
		buf.WriteByte(PQ_DEVICE_CONNECTED | byte(cmd.Device.Attrs.DeviceType))
	} else {
		buf.WriteByte(PQ_DEVICE_NOT_CONNECT | byte(cmd.Device.Attrs.DeviceType))
	}
	//byte 1
	//PAGE CODE
	buf.WriteByte(0x83)
	//PAGE LENGTH
	binary.Write(buf, binary.BigEndian, pageLength)
	buf.Write(data)
	return buf, pageLength
}

func SPCInquiry(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		allocationLength uint16
		pageLength       uint16
		additionLength   byte
		buf                     = &bytes.Buffer{}
		data             []byte = []byte{}
		addBuf                  = &bytes.Buffer{}
		addBufData       []byte = []byte{}
		//b                byte   = 0x75
		scb   []byte = cmd.SCB.Bytes()
		pcode byte   = scb[2]
		evpd  bool   = false

		vendorID   = make([]byte, 8)
		productID  = make([]byte, 16)
		productRev = make([]byte, 4)
	)

	allocationLength = util.GetUnalignedUint16(scb[3:5])

	if scb[1]&0x01 > 0 {
		evpd = true
	}

	if cmd.Device == nil {
		goto sense
	}

	if evpd {
		switch pcode {
		case 0x00:
			buf, pageLength = InquiryPage0x00(host, cmd)

		case 0x80:
			buf, pageLength = InquiryPage0x80(host, cmd)

		case 0x83:
			buf, pageLength = InquiryPage0x83(host, cmd)

		default:
			goto sense
		}
		data = buf.Bytes()
		if allocationLength < pageLength {
			cmd.InSDBBuffer.Buffer = bytes.NewBuffer(data[0:allocationLength])
		} else {
			cmd.InSDBBuffer.Buffer = bytes.NewBuffer(data[0:])
		}
	} else {
		//byte 5
		//SCCS(0) AAC(0) TPGS(0) 3PC(0) PROTECT(0)
		addBuf.WriteByte(INQUIRY_TPGS_IMPLICIT)
		//byte 6
		//ENCSERV(0) VS(0) MULTIP(0) ADDR16(0)
		addBuf.WriteByte(0x00)
		//byte 7
		//WBUS16(0) SYNC(0) CMDQUE(1) VS1(0)
		addBuf.WriteByte(INQUIRY_CMDQUE)

		copy(vendorID, []byte(fmt.Sprintf("%-8s", cmd.Device.Attrs.VendorID)))
		addBuf.Write(vendorID)

		copy(productID, []byte(fmt.Sprintf("%-16s", cmd.Device.Attrs.ProductID)))
		addBuf.Write(productID)

		copy(productRev, []byte(fmt.Sprintf("%-4s", cmd.Device.Attrs.ProductRev)))
		addBuf.Write(productRev)
		//Vendor specific(20 bytes)
		for i := 0; i < 20; i++ {
			addBuf.WriteByte(0x00)
		}
		//byte 56
		addBuf.WriteByte(0x00)
		//byte 57
		addBuf.WriteByte(0x00)
		//VERSION DESCRIPTOR 1 ~ 8
		binary.Write(addBuf, binary.BigEndian, cmd.Device.Attrs.VersionDesction)

		addBufData = addBuf.Bytes()
		additionLength = byte(len(addBufData))

		//Write header
		//byte 0
		//PERIPHERAL QUALIFIER, PERIPHERAL DEVICE TYPE
		if cmd.Device.Attrs.Online {
			buf.WriteByte(PQ_DEVICE_CONNECTED | byte(cmd.Device.Attrs.DeviceType))
		} else {
			buf.WriteByte(PQ_DEVICE_NOT_CONNECT | byte(cmd.Device.Attrs.DeviceType))
		}
		// byte 1
		// RMB(0) LU_CONG(0)
		buf.WriteByte(0x00)
		// byte 2
		// VERSION
		buf.WriteByte(VERSION_WITHDRAW_SPC3)
		// byte 3
		// Reserved, Reserved, NORMACA, HISUP, RESPONSE DATA FORMAT
		buf.WriteByte(INQUIRY_HISUP | INQUIRY_STANDARD_FORMAT)
		// byte 4
		// ADDITIONAL LENGTH
		buf.WriteByte(additionLength)

		buf.Write(addBufData)
		data = buf.Bytes()
		if allocationLength < uint16(additionLength) {
			cmd.InSDBBuffer.Buffer = bytes.NewBuffer(data[0:allocationLength])
		} else {
			cmd.InSDBBuffer.Buffer = bytes.NewBuffer(data[0:])
		}
	}

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

	remainLength = allocationLength
	if _, ok := cmd.Target.Devices[0]; !ok {
		availLength = 8 * uint32(len(cmd.Target.Devices)+1)
	} else {
		availLength = 8 * uint32(len(cmd.Target.Devices))
	}

	// LUN list length
	buf.Write(util.MarshalUint32(availLength))
	cmd.InSDBBuffer.Resid = int32(actualLength)

	// Skip through to byte 4, Reserved
	for i := 0; i < 4; i++ {
		buf.WriteByte(0x00)
	}

	//For LUN0
	if _, ok := cmd.Target.Devices[0]; !ok {
		buf.Write(util.MarshalUint64(0))
		remainLength -= 8
	}

	for lun := range cmd.Target.Devices {
		if remainLength > 0 {
			if lun > 0xff {
				lun = (0x01 << 30) | (0x3fff&lun)<<16
			} else {
				lun = (0x3fff & lun) << 16
			}
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

func SPCReportSupportedOperationCodes(host int, cmd *api.SCSICommand) api.SAMStat {
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

// This is useful for the various commands using the SERVICE ACTION format.
func SPCServiceAction(host int, cmd *api.SCSICommand) api.SAMStat {

	scb := cmd.SCB.Bytes()
	opcode := int(scb[0])
	action := uint8(scb[1] & 0x1F)
	serviceAction := cmd.Device.DeviceProtocol.PerformServiceAction(opcode, action)
	if serviceAction == nil {
		cmd.InSDBBuffer.Resid = 0
		BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
		return api.SAMStatCheckCondition
	} else {
		fnop := serviceAction.(*SCSIServiceAction)
		return fnop.CommandPerformFunc(host, cmd)
	}
}

func SPCPRReadKeys(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		buf                     = &bytes.Buffer{}
		data             []byte = []byte{}
		addBuf                  = &bytes.Buffer{}
		allocationLength uint16
		additionLength   uint32
	)
	tgtName := cmd.Target.Name
	devUUID := cmd.Device.UUID
	scsiResOp := GetSCSIReservationOperator()
	PRGeneration, _ := scsiResOp.GetPRGeneration(tgtName, devUUID)
	resList := scsiResOp.GetReservationList(tgtName, devUUID)
	length, _ := SCSICDBBufXLength(cmd.SCB.Bytes())

	allocationLength = uint16(length)
	if allocationLength < 8 {
		goto sense
	}

	for _, res := range resList {
		addBuf.Write(util.MarshalUint64(res.Key))
	}
	additionLength = uint32(len(addBuf.Bytes()))

	buf.Write(util.MarshalUint32(PRGeneration))
	buf.Write(util.MarshalUint32(additionLength))
	buf.Write(addBuf.Bytes())
	data = buf.Bytes()
	if allocationLength < uint16(additionLength) {
		cmd.InSDBBuffer.Buffer = bytes.NewBuffer(data[0:allocationLength])
	} else {
		cmd.InSDBBuffer.Buffer = bytes.NewBuffer(data)
	}

	cmd.InSDBBuffer.Resid = int32(additionLength)
	return api.SAMStatGood
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCPRReadReservation(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		buf                     = &bytes.Buffer{}
		data             []byte = []byte{}
		addBuf                  = &bytes.Buffer{}
		allocationLength uint16
		additionLength   uint32
	)
	tgtName := cmd.Target.Name
	devUUID := cmd.Device.UUID
	scsiResOp := GetSCSIReservationOperator()
	PRGeneration, _ := scsiResOp.GetPRGeneration(tgtName, devUUID)
	curRes := scsiResOp.GetCurrentReservation(tgtName, devUUID)

	length, _ := SCSICDBBufXLength(cmd.SCB.Bytes())
	allocationLength = uint16(length)
	if allocationLength < 8 {
		goto sense
	}

	if curRes == nil {
		additionLength = 0
	} else {
		addBuf.Write(util.MarshalUint64(curRes.Key))
		//Obsolete
		addBuf.WriteByte(0x00)
		addBuf.WriteByte(0x00)
		addBuf.WriteByte(0x00)
		addBuf.WriteByte(0x00)
		//Reserved
		addBuf.WriteByte(0x00)
		//SCOPE and TYPE
		scope_type := (curRes.Scope << 4) | curRes.Type
		addBuf.WriteByte(scope_type)
		additionLength = uint32(0x10)
	}

	buf.Write(util.MarshalUint32(PRGeneration))
	buf.Write(util.MarshalUint32(additionLength))
	buf.Write(addBuf.Bytes())
	data = buf.Bytes()
	if allocationLength < uint16(additionLength) {
		cmd.InSDBBuffer.Buffer = bytes.NewBuffer(data[0:allocationLength])
	} else {
		cmd.InSDBBuffer.Buffer = bytes.NewBuffer(data)
	}

	cmd.InSDBBuffer.Resid = int32(additionLength)
	return api.SAMStatGood

sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
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

func reservationCheck(host int, cmd *api.SCSICommand) bool {
	var (
		paramLen uint32
		buf      []byte = cmd.OutSDBBuffer.Buffer.Bytes()
	)
	length, _ := SCSICDBBufXLength(cmd.SCB.Bytes())
	paramLen = uint32(length)
	if paramLen != 24 {
		return false
	}
	spec_i_pt := uint8(buf[20] & 0x08)
	all_tg_pt := uint8(buf[20] & 0x04)
	aptpl := uint8(buf[20] & 0x01)
	/* Currently, We don't support these flags */
	if (spec_i_pt | all_tg_pt | aptpl) > 0 {
		return false
	}
	return true
}

func SPCPRRegister(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		buf       []byte = cmd.OutSDBBuffer.Buffer.Bytes()
		scb       []byte = cmd.SCB.Bytes()
		ignoreKey bool   = false
		ok        bool   = false
		resKey    uint64
		sAResKey  uint64
	)

	tgtName := cmd.Target.Name
	devUUID := cmd.Device.UUID
	scsiResOp := GetSCSIReservationOperator()
	res := scsiResOp.GetReservation(tgtName, devUUID, cmd.ITNexusID)

	if scb[1] == PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY {
		ignoreKey = true
	}
	ok = reservationCheck(host, cmd)
	if !ok {
		goto sense
	}
	resKey = util.GetUnalignedUint64(buf[0:8])
	sAResKey = util.GetUnalignedUint64(buf[8:16])

	if res != nil {
		if ignoreKey || resKey == res.Key {
			if sAResKey != 0 {
				res.Key = sAResKey
			} else {
				scsiResOp.DeleteAndRemoveReservation(tgtName, devUUID, res)
			}
		} else {
			return api.SAMStatReservationConflict
		}
	} else {
		if ignoreKey || resKey == 0 {
			if sAResKey != 0 {
				newRes := &api.SCSIReservation{
					ID:        uuid.NewV1(),
					Key:       sAResKey,
					ITNexusID: cmd.ITNexusID,
				}
				scsiResOp.AddReservation(tgtName, devUUID, newRes)
			}
		} else {
			return api.SAMStatReservationConflict
		}
	}
	scsiResOp.IncPRGeneration(tgtName, devUUID)
	scsiResOp.Save(tgtName, devUUID)
	return api.SAMStatGood

sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCPRReserve(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		scb      []byte = cmd.SCB.Bytes()
		curRes   *api.SCSIReservation
		res      *api.SCSIReservation
		ok       bool = false
		resScope uint8
		resType  uint8
	)

	tgtName := cmd.Target.Name
	devUUID := cmd.Device.UUID
	scsiResOp := GetSCSIReservationOperator()

	ok = reservationCheck(host, cmd)
	if !ok {
		goto sense
	}

	resScope = scb[2] & 0xf0 >> 4
	resType = scb[2] & 0x0f

	switch resType {
	case PR_TYPE_WRITE_EXCLUSIVE_REGONLY,
		PR_TYPE_EXCLUSIVE_ACCESS_REGONLY,
		PR_TYPE_WRITE_EXCLUSIVE_ALLREG,
		PR_TYPE_EXCLUSIVE_ACCESS_ALLREG:
		break
	default:
		goto sense
	}
	if resScope != PR_LU_SCOPE {
		goto sense
	}

	res = scsiResOp.GetReservation(tgtName, devUUID, cmd.ITNexusID)
	if res == nil {
		return api.SAMStatReservationConflict
	}

	curRes = scsiResOp.GetCurrentReservation(tgtName, devUUID)
	if curRes != nil {
		if !scsiResOp.IsCurrentReservation(tgtName, devUUID, res) {
			return api.SAMStatReservationConflict
		}

		if curRes.Type != resType ||
			curRes.Scope != resScope {
			return api.SAMStatReservationConflict
		}
	}
	res.Scope = resScope
	res.Type = resType
	scsiResOp.SetCurrentReservation(tgtName, devUUID, res)
	scsiResOp.Save(tgtName, devUUID)
	return api.SAMStatGood
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCPRRelease(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		buf      []byte = cmd.OutSDBBuffer.Buffer.Bytes()
		scb      []byte = cmd.SCB.Bytes()
		curRes   *api.SCSIReservation
		res      *api.SCSIReservation
		resList  []*api.SCSIReservation
		ok       bool = false
		resKey   uint64
		resScope uint8
		resType  uint8
	)

	tgtName := cmd.Target.Name
	devUUID := cmd.Device.UUID
	scsiResOp := GetSCSIReservationOperator()

	ok = reservationCheck(host, cmd)
	if !ok {
		goto sense
	}

	resScope = scb[2] & 0xf0 >> 4
	resType = scb[2] & 0x0f
	resKey = util.GetUnalignedUint64(buf[0:8])

	res = scsiResOp.GetReservation(tgtName, devUUID, cmd.ITNexusID)
	if res == nil {
		return api.SAMStatReservationConflict
	}

	curRes = scsiResOp.GetCurrentReservation(tgtName, devUUID)
	if curRes == nil {
		return api.SAMStatGood
	}

	if !scsiResOp.IsCurrentReservation(tgtName, devUUID, res) {
		return api.SAMStatGood
	}

	if resKey != res.Key {
		return api.SAMStatReservationConflict
	}

	if curRes.Scope != resScope || curRes.Type != resType {
		cmd.InSDBBuffer.Resid = 0
		BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_RELEASE_OF_PERSISTENT_RESERVATION)
		return api.SAMStatCheckCondition
	}

	scsiResOp.SetCurrentReservation(tgtName, devUUID, nil)
	res.Scope = 0
	res.Type = 0

	switch resType {
	case PR_TYPE_WRITE_EXCLUSIVE,
		PR_TYPE_EXCLUSIVE_ACCESS,
		PR_TYPE_WRITE_EXCLUSIVE_REGONLY,
		PR_TYPE_EXCLUSIVE_ACCESS_REGONLY,
		PR_TYPE_WRITE_EXCLUSIVE_ALLREG,
		PR_TYPE_EXCLUSIVE_ACCESS_ALLREG:
		break
	default:
		goto sense
	}

	resList = scsiResOp.GetReservationList(tgtName, devUUID)
	for _, tmpRes := range resList {
		if tmpRes.ID == res.ID {
			continue
		}
		//TODO send sense code
	}
	scsiResOp.Save(tgtName, devUUID)
	return api.SAMStatGood
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCPRClear(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		buf    []byte = cmd.OutSDBBuffer.Buffer.Bytes()
		curRes *api.SCSIReservation
		res    *api.SCSIReservation
		ok     bool = false
		resKey uint64
	)

	tgtName := cmd.Target.Name
	devUUID := cmd.Device.UUID
	scsiResOp := GetSCSIReservationOperator()
	resList := scsiResOp.GetReservationList(tgtName, devUUID)

	ok = reservationCheck(host, cmd)
	if !ok {
		goto sense
	}

	resKey = util.GetUnalignedUint64(buf[0:8])

	res = scsiResOp.GetReservation(tgtName, devUUID, cmd.ITNexusID)

	if res == nil {
		return api.SAMStatReservationConflict
	}

	if res.Key != resKey {
		return api.SAMStatReservationConflict
	}

	curRes = scsiResOp.GetCurrentReservation(tgtName, devUUID)

	if curRes != nil {
		curRes.Scope = 0
		curRes.Type = 0
		scsiResOp.SetCurrentReservation(tgtName, devUUID, nil)
	}

	for _, tmpRes := range resList {
		if tmpRes != res {
			//TODO send sense code
		}
		scsiResOp.DeleteAndRemoveReservation(tgtName, devUUID, tmpRes)
	}
	scsiResOp.IncPRGeneration(tgtName, devUUID)
	scsiResOp.Save(tgtName, devUUID)
	return api.SAMStatGood
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCPRPreempt(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		buf          []byte = cmd.OutSDBBuffer.Buffer.Bytes()
		scb          []byte = cmd.SCB.Bytes()
		ok           bool   = false
		resKey       uint64
		sAResKey     uint64
		res          *api.SCSIReservation
		curRes       *api.SCSIReservation
		resReleased  bool
		removeAllRes bool
		resScope     uint8
		resType      uint8
	)

	tgtName := cmd.Target.Name
	devUUID := cmd.Device.UUID
	scsiResOp := GetSCSIReservationOperator()
	resList := scsiResOp.GetReservationList(tgtName, devUUID)

	ok = reservationCheck(host, cmd)
	if !ok {
		goto sense
	}
	resScope = scb[2] & 0xf0 >> 4
	resType = scb[2] & 0x0f
	resKey = util.GetUnalignedUint64(buf[0:8])
	sAResKey = util.GetUnalignedUint64(buf[8:16])

	res = scsiResOp.GetReservation(tgtName, devUUID, cmd.ITNexusID)

	if res == nil {
		return api.SAMStatReservationConflict
	}

	if res.Key != resKey {
		return api.SAMStatReservationConflict
	}

	if sAResKey != 0 {
		ok = scsiResOp.IsKeyExists(tgtName, devUUID, sAResKey)
		if ok {
			return api.SAMStatReservationConflict
		}
	}

	curRes = scsiResOp.GetCurrentReservation(tgtName, devUUID)
	if curRes != nil {
		if curRes.Type == PR_TYPE_WRITE_EXCLUSIVE_ALLREG ||
			curRes.Type == PR_TYPE_EXCLUSIVE_ACCESS_ALLREG {
			if sAResKey == 0 {
				if resType != curRes.Type ||
					resScope != curRes.Scope {
					resReleased = true
				}
				res.Type = resType
				res.Scope = resScope
				scsiResOp.SetCurrentReservation(tgtName, devUUID, res)
				removeAllRes = true
			}
		} else {
			if curRes.Key == resKey {
				if resType != curRes.Type ||
					resScope != curRes.Scope {
					resReleased = true
				}
				res.Type = resType
				res.Scope = resScope
				scsiResOp.SetCurrentReservation(tgtName, devUUID, res)
			} else {
				if sAResKey == 0 {
					goto sense
				}
			}
		}
	}

	for _, tmpRes := range resList {
		if tmpRes == res {
			continue
		}

		if res.Key == resKey || removeAllRes {
			//TODO send sense code
			scsiResOp.RemoveReservation(tgtName, devUUID, res)
		} else {
			if resReleased {
				//TODO send sense code
			}
		}
	}
	scsiResOp.IncPRGeneration(tgtName, devUUID)
	scsiResOp.Save(tgtName, devUUID)
	return api.SAMStatGood
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
}

func SPCPRRegisterAndMove(host int, cmd *api.SCSICommand) api.SAMStat {
	var (
		buf                 []byte = cmd.OutSDBBuffer.Buffer.Bytes()
		scb                 []byte = cmd.SCB.Bytes()
		resKey              uint64
		sAResKey            uint64
		curRes, dstReg, res *api.SCSIReservation
		paramListLen        uint32
		unreg               uint8
		aptpl               uint8
		tpidDataLen         uint32
		//idLen        uint32
	)

	tgtName := cmd.Target.Name
	devUUID := cmd.Device.UUID
	scsiResOp := GetSCSIReservationOperator()
	resList := scsiResOp.GetReservationList(tgtName, devUUID)

	paramListLen = util.GetUnalignedUint32(scb[5:9])
	if paramListLen < 24 {
		goto sense
	}
	aptpl = buf[17] & 0x01
	if aptpl != 0 { /* no reported in capabilities */
		goto sense
	}

	unreg = buf[17] & 0x02

	resKey = util.GetUnalignedUint64(buf[0:8])
	sAResKey = util.GetUnalignedUint64(buf[8:16])

	tpidDataLen = util.GetUnalignedUint32(buf[20:25])
	if tpidDataLen < 24 || (tpidDataLen%4) != 0 {
		goto sense
	}

	if (paramListLen - 24) < tpidDataLen {
		goto sense
	}

	res = scsiResOp.GetReservation(tgtName, devUUID, cmd.ITNexusID)
	curRes = scsiResOp.GetCurrentReservation(tgtName, devUUID)
	if res == nil {
		if curRes != nil {
			return api.SAMStatReservationConflict
		} else {
			goto sense
		}
	}

	if scsiResOp.IsCurrentReservation(tgtName, devUUID, res) {
		return api.SAMStatGood
	}

	if res.Key != resKey {
		return api.SAMStatReservationConflict
	}

	if sAResKey == 0 {
		return api.SAMStatReservationConflict
	}

	for _, dstReg = range resList {
		if dstReg.Key == sAResKey {
			goto found
		}
	}

	goto sense
found:
	//TODO check transportid
	scsiResOp.SetCurrentReservation(tgtName, devUUID, dstReg)
	if unreg != 0 {
		scsiResOp.RemoveReservation(tgtName, devUUID, res)
	}
	scsiResOp.IncPRGeneration(tgtName, devUUID)
	scsiResOp.Save(tgtName, devUUID)
	return api.SAMStatGood
sense:
	cmd.InSDBBuffer.Resid = 0
	BuildSenseData(cmd, ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB)
	return api.SAMStatCheckCondition
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
