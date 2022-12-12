/*
Copyright 2017 The GoStor Authors All rights reserved.

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
	"io"
	"net"
	"sort"
	"sync"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/util"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

const (
	CONN_STATE_FREE           = 0
	CONN_STATE_SECURITY       = 1
	CONN_STATE_SECURITY_AUTH  = 2
	CONN_STATE_SECURITY_DONE  = 3
	CONN_STATE_SECURITY_LOGIN = 4
	CONN_STATE_SECURITY_FULL  = 5
	CONN_STATE_LOGIN          = 6
	CONN_STATE_LOGIN_FULL     = 7
	CONN_STATE_FULL           = 8
	CONN_STATE_KERNEL         = 9
	CONN_STATE_CLOSE          = 10
	CONN_STATE_EXIT           = 11
	CONN_STATE_SCSI           = 12
	CONN_STATE_INIT           = 13
	CONN_STATE_START          = 14
	CONN_STATE_READY          = 15
)

var (
	DATAIN  byte = 0x01
	DATAOUT byte = 0x10
)

type SendPackage struct {
	headBuf []byte
	dataBuf []byte
}

type iscsiConnection struct {
	id          uuid.UUID
	scsiCmdChan chan *ISCSICommand
	ConnNum     int
	state       int
	authState   int
	session     *ISCSISession
	tid         int
	cid         uint16
	txIOState   int
	refcount    int
	conn        net.Conn

	req *ISCSICommand

	loginParam *iscsiLoginParam

	// StatSN - the status sequence number on this connection
	statSN uint32
	// ExpStatSN - the expected status sequence number on this connection
	expStatSN uint32
	// CmdSN - the command sequence number at the target
	cmdSN uint32
	// ExpCmdSN - the next expected command sequence number at the target
	expCmdSN uint32
	// MaxCmdSN - the maximum CmdSN acceptable at the target from this initiator
	maxCmdSN                 uint32
	maxRecvDataSegmentLength uint32
	maxBurstLength           uint32
	maxSeqCount              uint32

	readLock      *sync.RWMutex
	txWorkChan    chan *SendPackage
	txWorkBufChan chan []byte

	bufPool    [bufNum][]byte
	bufPoolMap map[uint32]bool
	poolLock   sync.RWMutex
}

type taskState int

const (
	taskPending taskState = 0
	taskSCSI    taskState = 1
)

type iscsiTask struct {
	tag                uint32
	conn               *iscsiConnection
	cmd                *ISCSICommand
	scmd               *api.SCSICommand
	state              taskState
	expectedDataLength int64
	result             byte

	offset     int
	r2tCount   int
	unsolCount int
	expR2TSN   int

	r2tSN uint32
}

func (c *iscsiConnection) init() {
	c.id = uuid.NewV1()
	c.scsiCmdChan = make(chan *ISCSICommand, workChanNum)
	c.state = CONN_STATE_FREE
	c.refcount = 1
	c.readLock = new(sync.RWMutex)
	c.loginParam.sessionParam = []ISCSISessionParam{}
	c.loginParam.tgtCSG = LoginOperationalNegotiation
	c.loginParam.tgtNSG = LoginOperationalNegotiation
	for _, param := range sessionKeys {
		c.loginParam.sessionParam = append(c.loginParam.sessionParam,
			ISCSISessionParam{idx: param.idx, Value: param.def})
	}
	sort.Sort(c.loginParam.sessionParam)
}

func (c *iscsiConnection) readData(buf []byte) (int, error) {
	length, err := io.ReadFull(c.conn, buf)
	if err != nil {
		return -1, err
	}
	return length, nil
}

func (c *iscsiConnection) write(resp []byte) (int, error) {
	return c.conn.Write(resp)
}

func (c *iscsiConnection) close() {
	c.conn.Close()
}

func (conn *iscsiConnection) ReInstatement(newConn *iscsiConnection) {
	conn.close()
	conn.conn = newConn.conn
}

func (conn *iscsiConnection) buildRespPackage(oc OpCode, task *iscsiTask, cmd *ISCSICommand) (*ISCSICommand, error) {
	conn.txIOState = IOSTATE_TX_BHS
	conn.statSN += 1
	req := cmd
	if task != nil {
		req = task.cmd
	}
	resp := &ISCSICommand{
		StatSN:          req.ExpStatSN,
		TaskTag:         req.TaskTag,
		ExpectedDataLen: req.ExpectedDataLen,
	}
	log.Debugf("buildRespPackage TaskTag %x, oc %v ", resp.TaskTag, oc)
	if conn.session != nil {
		resp.ExpCmdSN = conn.session.ExpCmdSN
		resp.MaxCmdSN = conn.session.ExpCmdSN + conn.session.MaxQueueCommand
	}
	switch oc {
	case OpReady:
		resp.OpCode = OpReady
		resp.R2TSN = task.r2tSN
		resp.Final = true
		resp.BufferOffset = uint32(task.offset)
		resp.DesiredLength = uint32(task.r2tCount)
		if val := conn.loginParam.sessionParam[ISCSI_PARAM_MAX_BURST].Value; task.r2tCount > int(val) {
			resp.DesiredLength = uint32(val)
		}
	case OpSCSIIn, OpSCSIResp:
		resp.OpCode = oc
		resp.SCSIOpCode = req.SCSIOpCode
		resp.Immediate = true
		resp.Final = true
		resp.SCSIResponse = 0x00
		resp.HasStatus = true
		scmd := task.scmd
		resp.Status = scmd.Result
		if scmd.Result != 0 && scmd.SenseBuffer != nil {
			length := util.MarshalUint32(scmd.SenseBuffer.Length)
			resp.RawData = append(length[2:4], scmd.SenseBuffer.Buffer...)
			if scmd.InSDBBuffer != nil {
				freeBufPool(conn, scmd.InSDBBuffer.Buffer)

			}
		} else if scmd.Direction == api.SCSIDataRead || scmd.Direction == api.SCSIDataWrite {
			if scmd.InSDBBuffer != nil {
				resp.Resid = scmd.InSDBBuffer.Resid
				if resp.Resid != 0 && resp.Resid < scmd.InSDBBuffer.Length {
					resp.RawData = scmd.InSDBBuffer.Buffer[:resp.Resid]
				} else {
					resp.RawData = scmd.InSDBBuffer.Buffer
				}
			} else {
				resp.RawData = []byte{}
			}
		}

	case OpNoopIn, OpReject:
		resp.OpCode = oc
		resp.Final = true
		resp.NSG = FullFeaturePhase
		resp.ExpCmdSN = req.CmdSN + 1
	case OpSCSITaskResp:
		resp.OpCode = oc
		resp.Final = true
		resp.NSG = FullFeaturePhase
		resp.ExpCmdSN = req.CmdSN + 1
		resp.Result = task.result
	case OpLoginResp:
		resp.OpCode = OpLoginResp
		resp.Transit = conn.loginParam.tgtTrans
		resp.CSG = req.CSG
		resp.NSG = conn.loginParam.tgtNSG
		resp.ExpCmdSN = req.CmdSN
		resp.MaxCmdSN = req.CmdSN
		if req.CSG != SecurityNegotiation {
			negoKeys, err := conn.processLoginData(cmd)
			if err != nil {
				return resp, err
			}
			if !conn.loginParam.keyDeclared {
				negoKeys = loginKVDeclare(conn, negoKeys)
				conn.loginParam.keyDeclared = true
			}
			resp.RawData = util.MarshalKVText(negoKeys)
		}
	}

	return resp, nil
}

func (conn *iscsiConnection) State() string {
	switch conn.state {
	case CONN_STATE_FREE:
		return "free"
	case CONN_STATE_SECURITY:
		return "begin security"
	case CONN_STATE_SECURITY_AUTH:
		return "security auth"
	case CONN_STATE_SECURITY_DONE:
		return "done security"
	case CONN_STATE_SECURITY_LOGIN:
		return "security login"
	case CONN_STATE_SECURITY_FULL:
		return "security full"
	case CONN_STATE_LOGIN:
		return "begin login"
	case CONN_STATE_LOGIN_FULL:
		return "done login"
	case CONN_STATE_FULL:
		return "full feature"
	case CONN_STATE_KERNEL:
		return "kernel"
	case CONN_STATE_CLOSE:
		return "close"
	case CONN_STATE_EXIT:
		return "exit"
	case CONN_STATE_SCSI:
		return "scsi"
	case CONN_STATE_INIT:
		return "init"
	case CONN_STATE_START:
		return "start"
	case CONN_STATE_READY:
		return "ready"
	}
	return ""
}
