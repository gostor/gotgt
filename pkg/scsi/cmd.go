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

type SCSIPRServiceAction byte
type SCSIPRType byte

var (
	/* PERSISTENT_RESERVE_IN service action codes */
	PR_IN_READ_KEYS           SCSIPRServiceAction = 0x00
	PR_IN_READ_RESERVATION    SCSIPRServiceAction = 0x01
	PR_IN_REPORT_CAPABILITIES SCSIPRServiceAction = 0x02
	PR_IN_READ_FULL_STATUS    SCSIPRServiceAction = 0x03

	/* PERSISTENT_RESERVE_OUT service action codes */
	PR_OUT_REGISTER                         SCSIPRServiceAction = 0x00
	PR_OUT_RESERVE                          SCSIPRServiceAction = 0x01
	PR_OUT_RELEASE                          SCSIPRServiceAction = 0x02
	PR_OUT_CLEAR                            SCSIPRServiceAction = 0x03
	PR_OUT_PREEMPT                          SCSIPRServiceAction = 0x04
	PR_OUT_PREEMPT_AND_ABORT                SCSIPRServiceAction = 0x05
	PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY SCSIPRServiceAction = 0x06
	PR_OUT_REGISTER_AND_MOVE                SCSIPRServiceAction = 0x07

	/* Persistent Reservation scope */
	PR_LU_SCOPE byte = 0x00

	/* Persistent Reservation Type Mask format */
	PR_TYPE_WRITE_EXCLUSIVE          SCSIPRType = 0x01
	PR_TYPE_EXCLUSIVE_ACCESS         SCSIPRType = 0x03
	PR_TYPE_WRITE_EXCLUSIVE_REGONLY  SCSIPRType = 0x05
	PR_TYPE_EXCLUSIVE_ACCESS_REGONLY SCSIPRType = 0x06
	PR_TYPE_WRITE_EXCLUSIVE_ALLREG   SCSIPRType = 0x07
	PR_TYPE_EXCLUSIVE_ACCESS_ALLREG  SCSIPRType = 0x08
)

const (
	CBD_GROUPID_0 = iota
	CBD_GROUPID_1
	CBD_GROUPID_2
	CBD_GROUPID_3
	CBD_GROUPID_4
	CBD_GROUPID_5
	CBD_GROUPID_6
	CBD_GROUPID_7
)

const (
	CDB_GROUP0 = 6  /*  6-byte commands */
	CDB_GROUP1 = 10 /* 10-byte commands */
	CDB_GROUP2 = 10 /* 10-byte commands */
	CDB_GROUP3 = 0  /* reserved */
	CDB_GROUP4 = 16 /* 16-byte commands */
	CDB_GROUP5 = 12 /* 12-byte commands */
	CDB_GROUP6 = 0  /* vendor specific  */
	CDB_GROUP7 = 0  /* vendor specific  */
)

func SCSICDBGroupID(opcode byte) byte {
	return ((opcode >> 5) & 0x7)
}
