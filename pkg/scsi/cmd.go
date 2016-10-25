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

import (
	"github.com/gostor/gotgt/pkg/util"
)

const (
	/* PERSISTENT_RESERVE_IN service action codes */
	PR_IN_READ_KEYS           byte = 0x00
	PR_IN_READ_RESERVATION    byte = 0x01
	PR_IN_REPORT_CAPABILITIES byte = 0x02
	PR_IN_READ_FULL_STATUS    byte = 0x03

	/* PERSISTENT_RESERVE_OUT service action codes */
	PR_OUT_REGISTER                         byte = 0x00
	PR_OUT_RESERVE                          byte = 0x01
	PR_OUT_RELEASE                          byte = 0x02
	PR_OUT_CLEAR                            byte = 0x03
	PR_OUT_PREEMPT                          byte = 0x04
	PR_OUT_PREEMPT_AND_ABORT                byte = 0x05
	PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY byte = 0x06
	PR_OUT_REGISTER_AND_MOVE                byte = 0x07

	/* Persistent Reservation scope */
	PR_LU_SCOPE byte = 0x00

	/* Persistent Reservation Type Mask format */
	PR_TYPE_WRITE_EXCLUSIVE          byte = 0x01
	PR_TYPE_EXCLUSIVE_ACCESS         byte = 0x03
	PR_TYPE_WRITE_EXCLUSIVE_REGONLY  byte = 0x05
	PR_TYPE_EXCLUSIVE_ACCESS_REGONLY byte = 0x06
	PR_TYPE_WRITE_EXCLUSIVE_ALLREG   byte = 0x07
	PR_TYPE_EXCLUSIVE_ACCESS_ALLREG  byte = 0x08
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

/*
 * Transfer Length (if any)
 * Parameter List Length (if any)
 * Allocation Length (if any)
 */
func SCSICDBBufXLength(scb []byte) (int64, bool) {
	var (
		opcode byte
		length int64
		group  byte
		ok     bool = true
	)
	opcode = scb[0]
	group = SCSICDBGroupID(opcode)

	switch group {
	case CBD_GROUPID_0:
		length = int64(scb[4])
	case CBD_GROUPID_1, CBD_GROUPID_2:
		length = int64(util.GetUnalignedUint16(scb[7:9]))
	case CBD_GROUPID_3:
		if opcode == 0x7F {
			length = int64(scb[7])
		} else {
			ok = false
		}
	case CBD_GROUPID_4:
		length = int64(util.GetUnalignedUint32(scb[6:10]))
	case CBD_GROUPID_5:
		length = int64(util.GetUnalignedUint32(scb[10:14]))
	default:
		ok = false
	}
	return length, ok
}
