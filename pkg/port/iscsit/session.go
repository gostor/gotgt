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

package iscsit

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/satori/go.uuid"
)

var (
	SESSION_NORMAL    int = 0
	SESSION_DISCOVERY int = 1
)

var DIGEST_CRC32C uint = 1 << 1
var DIGEST_NONE uint = 1 << 0
var DIGEST_ALL uint = DIGEST_NONE | DIGEST_CRC32C
var BHS_SIZE = 48

const (
	MAX_QUEUE_CMD_MIN = 1
	MAX_QUEUE_CMD_DEF = 128
	MAX_QUEUE_CMD_MAX = 512
)

const (
	ISCSI_PARAM_MAX_RECV_DLENGTH = iota
	ISCSI_PARAM_HDRDGST_EN
	ISCSI_PARAM_DATADGST_EN
	ISCSI_PARAM_INITIAL_R2T_EN
	ISCSI_PARAM_MAX_R2T
	ISCSI_PARAM_IMM_DATA_EN
	ISCSI_PARAM_FIRST_BURST
	ISCSI_PARAM_MAX_BURST
	ISCSI_PARAM_PDU_INORDER_EN
	ISCSI_PARAM_DATASEQ_INORDER_EN
	ISCSI_PARAM_ERL
	ISCSI_PARAM_IFMARKER_EN
	ISCSI_PARAM_OFMARKER_EN
	ISCSI_PARAM_DEFAULTTIME2WAIT
	ISCSI_PARAM_DEFAULTTIME2RETAIN
	ISCSI_PARAM_OFMARKINT
	ISCSI_PARAM_IFMARKINT
	ISCSI_PARAM_MAXCONNECTIONS
	/* iSCSI Extensions for RDMA (RFC5046) */
	ISCSI_PARAM_RDMA_EXTENSIONS
	ISCSI_PARAM_TARGET_RDSL
	ISCSI_PARAM_INITIATOR_RDSL
	ISCSI_PARAM_MAX_OUTST_PDU
	/* "local" parmas, never sent to the initiator */
	ISCSI_PARAM_FIRST_LOCAL
	ISCSI_PARAM_MAX_XMIT_DLENGTH = ISCSI_PARAM_FIRST_LOCAL
	ISCSI_PARAM_MAX_QUEUE_CMD
	/* must always be last */
	ISCSI_PARAM_MAX
)

type ISCSISessionParam struct {
	State int
	Value uint
}

/*
 * The defaults here are according to the spec and must not be changed,
 * otherwise the initiator may make the wrong assumption.  If you want
 * to change a value, edit the value in iscsi_target_create.
 *
 * The param MaxXmitDataSegmentLength doesn't really exist.  It's a way
 * to remember the RDSL of the initiator, which defaults to 8k if he has
 * not told us otherwise.
 */
type iscsiSessionKeys struct {
	name string
	def  uint
	min  uint
	max  uint
}

var sessionKeys []iscsiSessionKeys = []iscsiSessionKeys{
	// ISCSI_PARAM_MAX_RECV_DLENGTH
	{"MaxRecvDataSegmentLength", 8192, 512, 16777215},
	// ISCSI_PARAM_HDRDGST_EN
	{"HeaderDigest", DIGEST_NONE, DIGEST_NONE, DIGEST_ALL},
	// ISCSI_PARAM_DATADGST_EN
	{"DataDigest", DIGEST_NONE, DIGEST_NONE, DIGEST_ALL},
	// ISCSI_PARAM_INITIAL_R2T_EN
	{"InitialR2T", 1, 0, 1},
	// ISCSI_PARAM_MAX_R2T
	{"MaxOutstandingR2T", 1, 1, 65535},
	// ISCSI_PARAM_IMM_DATA_EN
	{"ImmediateData", 1, 0, 1},
	// ISCSI_PARAM_FIRST_BURST
	{"FirstBurstLength", 65536, 512, 16777215},
	// ISCSI_PARAM_MAX_BURST
	{"MaxBurstLength", 262144, 512, 16777215},
	// ISCSI_PARAM_PDU_INORDER_EN
	{"DataPDUInOrder", 1, 0, 1},
	// ISCSI_PARAM_DATASEQ_INORDER_EN
	{"DataSequenceInOrder", 1, 0, 1},
	// ISCSI_PARAM_ERL
	{"ErrorRecoveryLevel", 0, 0, 2},
	// ISCSI_PARAM_IFMARKER_EN
	{"IFMarker", 0, 0, 1},
	// ISCSI_PARAM_OFMARKER_EN
	{"OFMarker", 0, 0, 1},
	// ISCSI_PARAM_DEFAULTTIME2WAIT
	{"DefaultTime2Wait", 2, 0, 3600},
	// ISCSI_PARAM_DEFAULTTIME2RETAIN
	{"DefaultTime2Retain", 20, 0, 3600},
	// ISCSI_PARAM_OFMARKINT
	{"OFMarkInt", 2048, 1, 65535},
	// ISCSI_PARAM_IFMARKINT
	{"IFMarkInt", 2048, 1, 65535},
	// ISCSI_PARAM_MAXCONNECTIONS
	{"MaxConnections", 1, 1, 65535},
	// ISCSI_PARAM_RDMA_EXTENSIONS
	{"RDMAExtensions", 0, 0, 1},
	// ISCSI_PARAM_TARGET_RDSL
	{"TargetRecvDataSegmentLength", 8192, 512, 16777215},
	// ISCSI_PARAM_INITIATOR_RDSL
	{"InitiatorRecvDataSegmentLength", 8192, 512, 16777215},
	// ISCSI_PARAM_MAX_OUTST_PDU
	{"MaxOutstandingUnexpectedPDUs", 0, 2, 4294967295},
	// "local" parmas, never sent to the initiator
	// ISCSI_PARAM_MAX_XMIT_DLENGTH
	{"MaxXmitDataSegmentLength", 8192, 512, 16777215},
	// ISCSI_PARAM_MAX_QUEUE_CMD
	{"MaxQueueCmd", MAX_QUEUE_CMD_DEF, MAX_QUEUE_CMD_MIN, MAX_QUEUE_CMD_MAX},
}

// Session is an iSCSI session.
type ISCSISession struct {
	Refcount       int
	Initiator      string
	InitiatorAlias string
	Target         *ISCSITarget
	ISID           uint64
	TSIH           uint64
	ITNexusID      uuid.UUID

	ExpCmdSN uint32
	// only one connection per session
	Connections     []*iscsiConnection
	Commands        []*ISCSICommand
	PendingTasks    taskQueue
	MaxQueueCommand uint32
	SessionParam    []ISCSISessionParam
	Info            string
	Rdma            int
}

type taskQueue []*iscsiTask

func (tq taskQueue) Len() int { return len(tq) }

func (tq taskQueue) Less(i, j int) bool {
	// We want Pop to give us the highest, not lowest, priority so we use greater than here.
	return tq[i].cmd.CmdSN > tq[j].cmd.CmdSN
}

func (tq taskQueue) Swap(i, j int) {
	tq[i], tq[j] = tq[j], tq[i]
}

func (tq *taskQueue) Push(x interface{}) {
	item := x.(*iscsiTask)
	*tq = append(*tq, item)
}

func (tq *taskQueue) Pop() interface{} {
	old := *tq
	n := len(old)
	item := old[n-1]
	*tq = old[0 : n-1]
	return item
}

// The BHS is 48 bytes long.  The Opcode and DataSegmentLength fields
// appear in all iSCSI PDUs.  In addition, when used, the Initiator Task
// Tag and Logical Unit Number always appear in the same location in the
// header.
type iscsiHeader struct {
	opcode    uint8
	flags     uint8 // Final bit
	rsvd2     [2]uint8
	hlength   uint8    // AHSs total length
	dlength   [3]uint8 // Data length
	lun       [8]uint8
	itt       uint8 // Initiator Task Tag
	ttt       uint8 // Target Task Tag
	statsn    uint8
	expStatSN uint8
	maxStatSN uint8
	other     [12]uint8
}

type iscsiPdu struct {
	bhs      iscsiHeader
	ahsSize  uint
	dataSize uint
}

// New creates a new session.
func (s *ISCSITargetService) NewISCSISession(conn *iscsiConnection, isid uint64) (*ISCSISession, error) {
	var (
		target *ISCSITarget
		tsih   uint64
	)

	for _, t := range s.iSCSITargets {
		if t.TID == conn.tid {
			target = t
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("No target found with tid(%d)", conn.tid)
	}

	for {
		rand.Seed(int64(time.Now().UTC().Nanosecond()))
		tsih = uint64(rand.Uint32())
		for _, s := range target.Sessions {
			if s.TSIH == tsih {
				tsih = 0
				break
			}
		}
		if tsih != 0 {
			break
		}
	}

	sess := &ISCSISession{
		TSIH:            tsih,
		ISID:            isid,
		Initiator:       conn.initiator,
		InitiatorAlias:  conn.initiatorAlias,
		Target:          target,
		Connections:     []*iscsiConnection{conn},
		SessionParam:    conn.sessionParam,
		MaxQueueCommand: uint32(conn.sessionParam[ISCSI_PARAM_MAX_QUEUE_CMD].Value),
		Rdma:            0,
		ExpCmdSN:        conn.expCmdSN,
	}
	conn.session = sess
	return sess, nil
}

/*
 * iSCSI I_T nexus identifer = (iSCSI Initiator Name + 'i' + ISID, iSCSI Target Name + 't' + Portal Group Tag)
 */
func GeniSCSIITNexusID(sess *ISCSISession) string {
	strID := fmt.Sprintf("%si0x%12x,%st%d",
		sess.Initiator, sess.ISID,
		sess.Target.SCSITarget.Name,
		sess.Connections[0].tpgt)
	return strID
}
