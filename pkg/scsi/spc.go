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
type ProtocolIdentifier int

var (
	PIV_FCP   ProtocolIdentifier = iota
	PIV_SPI   ProtocolIdentifier
	PIV_S3P   ProtocolIdentifier
	PIV_SBP   ProtocolIdentifier
	PIV_SRP   ProtocolIdentifier
	PIV_ISCSI ProtocolIdentifier
	PIV_SAS   ProtocolIdentifier
	PIV_ADT   ProtocolIdentifier
	PIV_ATA   ProtocolIdentifier
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
type DesignatorType int

var (
	DESG_VENDOR       DesignatorType = iota
	DESG_T10          DesignatorType
	DESG_EUI64        DesignatorType
	DESG_NAA          DesignatorType
	DESG_REL_TGT_PORT DesignatorType
	DESG_TGT_PORT_GRP DesignatorType
	DESG_LU_GRP       DesignatorType
	DESG_MD5          DesignatorType
	DESG_SCSI         DesignatorType
)

func SPCIllegalOp(host int, cmd *SCSICommand) error {
	return nil
}

func SPCInquiry(host int, cmd *SCSICommand) error {
	return nil
}

func SPCReportLuns(host int, cmd *SCSICommand) error {
	return nil
}

func SPCStartStop(host int, cmd *SCSICommand) error {
	return nil
}

func SPCTestUnit(host int, cmd *SCSICommand) error {
	return nil
}

func SPCPreventAllowMediaRemoval(host int, cmd *SCSICommand) error {
	return nil
}

func SPCModeSense(host int, cmd *SCSICommand) error {
	return nil
}

func SPCServiceAction(host int, cmd *SCSICommand) error {
	return nil
}

func SPCPRReadKeys(host int, cmd *SCSICommand) error {
	return nil
}

func SPCPRReadReservation(host int, cmd *SCSICommand) error {
	return nil
}

func SPCPRReportCapabilities(host int, cmd *SCSICommand) error {
	return nil
}

func SPCPRRegister(host int, cmd *SCSICommand) error {
	return nil
}

func SPCPRReserve(host int, cmd *SCSICommand) error {
	return nil
}

func SPCPRRelease(host int, cmd *SCSICommand) error {
	return nil
}

func SPCPRClear(host int, cmd *SCSICommand) error {
	return nil
}

func SPCPRPreempt(host int, cmd *SCSICommand) error {
	return nil
}

func SPCPRRegisterAndMove(host int, cmd *SCSICommand) error {
	return nil
}

func SPCRequestSense(host int, cmd *SCSICommand) error {
	return nil
}

func SPCSendDiagnostics(host int, cmd *SCSICommand) error {
}
