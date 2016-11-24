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

/*
 * SPCInquiry Implements SCSI INQUIRY command
 * The INQUIRY command requests the device server to return information regarding the logical unit and SCSI target device.
 *
 * Reference : SPC4r11
 * 6.6 - INQUIRY
 */
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

/*
 * SPCReportLuns Implements SCSI REPORT LUNS command
 * The REPORT LUNS command requests the device server to return the peripheral Device
 * logical unit inventory accessible to the I_T nexus.
 *
 * Reference : SPC4r11
 * 6.33 - REPORT LUNS
 */
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

/*
 * SPCTestUnit Implements SCSI TEST UNIT READY command
 * The TEST UNIT READY command requests the device server to indicate whether the logical unit is ready.
 *
 * Reference : SPC4r11
 * 6.47 - TEST UNIT READY
 */
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

/*
 * SPCModeSense Implement SCSI MODE SENSE(6) and MODE SENSE(10) command
 * The MODE SENSE command requests the device server to return the specified medium,
 * logical unit, or peripheral device parameters.
 *
 * Reference : SPC4r11
 * 6.11 - MODE SENSE(6)
 * 6.12 - MODE SENSE(10)
 */
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

/*
 * SPCSendDiagnostics Implements SCSI SEND DIAGNOSTIC command
 * The SEND DIAGNOSTIC command requests the device server to perform diagnostic operations
 * on the SCSI target device, on the logical unit, or on both.
 *
 * Reference : SPC4r11
 * 6.42 - SEND DIAGNOSTIC
 */
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

/*
 * SPCRequestSense Implements SCSI REQUEST SENSE command
 * The REQUEST SENSE command requests the device server to return parameter data that contains sense data.
 *
 * Reference : SPC4r11
 * 6.39 - REQUEST SENSE
 */
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
		data.Write(cmd.SenseBuffer.Bytes()[:actualLength])
	}
	cmd.InSDBBuffer.Resid = int32(actualLength)
	cmd.InSDBBuffer.Buffer = data

	// reset sense buffer in cmnd
	cmd.SenseBuffer = &bytes.Buffer{}
	cmd.SenseLength = 0

	return api.SAMStatGood
}
