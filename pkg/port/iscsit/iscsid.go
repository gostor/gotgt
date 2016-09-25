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
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime/debug"

	"github.com/golang/glog"
	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/port"
	"github.com/gostor/gotgt/pkg/scsi"
	"github.com/gostor/gotgt/pkg/util"
)

type ISCSITargetService struct {
	SCSI    *scsi.SCSITargetService
	Name    string
	Targets map[string]*ISCSITarget
}

func init() {
	port.RegisterTargetService("iscsi", NewISCSITargetService)
}

func NewISCSITargetService(base *scsi.SCSITargetService) (port.SCSITargetService, error) {
	return &ISCSITargetService{
		Name:    "iscsi",
		Targets: map[string]*ISCSITarget{},
		SCSI:    base,
	}, nil
}

func (s *ISCSITargetService) NewTarget(target string) (port.SCSITargetDriver, error) {
	if _, ok := s.Targets[target]; ok {
		return nil, fmt.Errorf("target name has been existed")
	}
	stgt, err := s.SCSI.NewSCSITarget(len(s.Targets), "iscsi", target)
	if err != nil {
		return nil, err
	}
	tgt := newISCSITarget(stgt)
	s.Targets[target] = tgt

	return tgt, nil
}

func (s *ISCSITargetService) Run() error {
	l, err := net.Listen("tcp", ":3260")
	if err != nil {
		glog.Error(err)
		os.Exit(1)
	}
	defer l.Close()

	for {
		glog.Info("Listening ...")
		conn, err := l.Accept()
		if err != nil {
			glog.Error(err)
		}
		glog.Info("Accepting ...")
		iscsiConn := &iscsiConnection{conn: conn}
		iscsiConn.init()
		iscsiConn.rxIOState = IOSTATE_RX_BHS

		glog.Infof("connection is connected from %s...\n", conn.RemoteAddr().String())
		// start a new thread to do with this command
		go s.handler(DATAIN, iscsiConn)
	}
	return nil
}

func (s *ISCSITargetService) handler(events byte, conn *iscsiConnection) {

	if events&DATAIN != 0 {
		glog.V(1).Infof("rx handler processing...")
		go s.rxHandler(conn)
	}
	if conn.state != CONN_STATE_CLOSE && events&DATAOUT != 0 {
		glog.V(1).Infof("tx handler processing...")
		s.txHandler(conn)
	}
	if conn.state == CONN_STATE_CLOSE {
		glog.Warningf("iscsi connection[%d] closed", conn.cid)
		conn.close()
	}
}

func (s *ISCSITargetService) rxHandler(conn *iscsiConnection) {
	var (
		hdigest uint = 0
		ddigest uint = 0
		final   bool = false
		cmd     *ISCSICommand
	)
	conn.readLock.Lock()
	defer conn.readLock.Unlock()
	if conn.state == CONN_STATE_SCSI {
		hdigest = conn.sessionParam[ISCSI_PARAM_HDRDGST_EN].Value & DIGEST_CRC32C
		ddigest = conn.sessionParam[ISCSI_PARAM_DATADGST_EN].Value & DIGEST_CRC32C
	}
	for {
		switch conn.rxIOState {
		case IOSTATE_RX_BHS:
			glog.Infof("rx handler: IOSTATE_RX_BHS")
			buf, length, err := conn.readData(BHS_SIZE)
			if err != nil {
				glog.Error(err)
				return
			}
			if length == 0 {
				glog.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
				return
			}
			conn.rxBuffer = buf
			cmd, err = parseHeader(buf)
			if err != nil {
				glog.Error(err)
				glog.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
				return
			}
			conn.req = cmd
			if length == BHS_SIZE && cmd.DataLen != 0 {
				conn.rxIOState = IOSTATE_RX_INIT_AHS
				break
			}
			glog.V(2).Infof("got command: \n%s", cmd.String())
			glog.V(2).Infof("got buffer: %v", buf)
			final = true
		case IOSTATE_RX_INIT_AHS:
			conn.rxIOState = IOSTATE_RX_DATA
			break
			if hdigest != 0 {
				conn.rxIOState = IOSTATE_RX_INIT_HDIGEST
			}
		case IOSTATE_RX_DATA:
			if ddigest != 0 {
				conn.rxIOState = IOSTATE_RX_INIT_DDIGEST
			}
			if cmd == nil {
				return
			}
			dl := ((cmd.DataLen + DataPadding - 1) / DataPadding) * DataPadding
			buf := []byte{}
			length := 0
			for length < dl {
				b, l, err := conn.readData(dl - length)
				if err != nil {
					glog.Error(err)
					return
				}
				length += l
				buf = append(buf, b...)
			}
			if length != dl {
				glog.V(2).Infof("get length is %d, but expected %d", length, dl)
				glog.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
				return
			}
			cmd.RawData = buf[:length]
			conn.rxBuffer = append(conn.rxBuffer, buf...)
			final = true
			glog.Infof("got command: \n%s", cmd.String())
		default:
			glog.Errorf("error %d %d\n", conn.state, conn.rxIOState)
			return
		}

		if final {
			break
		}
	}

	if conn.state == CONN_STATE_SCSI {
		s.scsiCommandHandler(conn)
	} else {
		conn.txIOState = IOSTATE_TX_BHS
		conn.resp = &ISCSICommand{}
		switch conn.req.OpCode {
		case OpLoginReq:
			glog.Infof("OpLoginReq")
			if err := s.iscsiExecLogin(conn); err != nil {
				glog.Error(err)
				glog.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
			}
		case OpLogoutReq:
			glog.Infof("OpLogoutReq")
			if err := iscsiExecLogout(conn); err != nil {
				glog.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
			}
		case OpTextReq:
			glog.Infof("OpTextReq")
			if err := s.iscsiExecText(conn); err != nil {
				glog.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
			}
		default:
			iscsiExecReject(conn)
		}
		glog.V(2).Infof("connection state is %v", conn.state)
		glog.V(2).Infof("%#v", conn.resp.String())
		s.handler(DATAOUT, conn)
	}
}

func (s *ISCSITargetService) iscsiExecLogin(conn *iscsiConnection) error {
	var (
		target *ISCSITarget
		cmd    = conn.req
	)
	conn.resp = &ISCSICommand{
		OpCode:   OpLoginResp,
		Transit:  true,
		CSG:      cmd.CSG,
		NSG:      FullFeaturePhase,
		StatSN:   cmd.ExpStatSN,
		TaskTag:  cmd.TaskTag,
		ExpCmdSN: cmd.CmdSN,
		MaxCmdSN: cmd.CmdSN,
		RawData: util.MarshalKVText([]util.KeyValue{
			{"HeaderDigest", "None"},
			{"DataDigest", "None"},
			{"ImmediateData", "Yes"},
			{"InitialR2T", "Yes"},
			{"MaxBurstLength", "262144"},
			{"FirstBurstLength", "65536"},
			{"DefaultTime2Wait", "2"},
			{"DefaultTime2Retain", "0"},
			{"MaxOutstandingR2T", "1"},
			{"IFMarker", "No"},
			{"OFMarker", "No"},
			{"DataPDUInOrder", "Yes"},
			{"DataSequenceInOrder", "Yes"},
		}),
	}
	pairs := util.ParseKVText(cmd.RawData)
	if initiatorName, ok := pairs["InitiatorName"]; ok {
		conn.initiator = initiatorName
	}
	if alias, ok := pairs["InitiatorAlias"]; ok {
		conn.initiatorAlias = alias
	}
	targetName := pairs["TargetName"]
	if sessType, ok := pairs["SessionType"]; ok {
		if sessType == "Normal" {
			conn.sessionType = SESSION_NORMAL
		} else {
			conn.sessionType = SESSION_DISCOVERY
		}
	}
	if conn.sessionType == SESSION_DISCOVERY {
		conn.tid = 0xffff
	} else {
		for _, t := range s.Targets {
			if t.SCSITarget.Name == targetName {
				target = t
				break
			}
		}
		if target == nil {
			conn.state = CONN_STATE_EXIT
			return fmt.Errorf("No target found with name(%s)", targetName)
		}
		conn.tid = target.TID
	}
	switch conn.state {
	case CONN_STATE_FREE:
		conn.state = CONN_STATE_SECURITY
	case CONN_STATE_SECURITY:
	}

	conn.state = CONN_STATE_LOGIN_FULL
	conn.expCmdSN = cmd.CmdSN
	conn.statSN += 1

	switch conn.sessionType {
	case SESSION_NORMAL:
		if conn.session == nil {
			// create a new session
			sess, err := s.NewISCSISession(conn)
			if err != nil {
				glog.Error(err)
				return err
			}
			conn.session = sess
		}
	case SESSION_DISCOVERY:

	}

	return nil
}

func iscsiExecLogout(conn *iscsiConnection) error {
	cmd := conn.req
	conn.resp = &ISCSICommand{
		OpCode:  OpLogoutResp,
		StatSN:  cmd.ExpStatSN,
		TaskTag: cmd.TaskTag,
	}
	if conn.session == nil {
		conn.resp.ExpCmdSN = cmd.CmdSN
		conn.resp.MaxCmdSN = cmd.CmdSN
	} else {
		conn.resp.ExpCmdSN = conn.session.ExpCmdSN
		conn.resp.MaxCmdSN = conn.session.ExpCmdSN + 10
	}
	return nil
}

func (s *ISCSITargetService) iscsiExecText(conn *iscsiConnection) error {
	var result = []util.KeyValue{}
	cmd := conn.req
	keys := util.ParseKVText(cmd.RawData)
	if st, ok := keys["SendTargets"]; ok {
		if st == "All" {
			list, err := s.SCSI.GetTargetList()
			if err != nil {
				return err
			}
			for _, t := range list {
				result = append(result, util.KeyValue{"TargetName", t.Name})
				//result = append(result, util.KeyValue{"TargetAddress", "172.16.69.1:3260,1"})
				result = append(result, util.KeyValue{"TargetAddress", "127.0.0.1:3260,1"})
			}
		}
	}

	conn.resp = &ISCSICommand{
		OpCode:   OpTextResp,
		Final:    true,
		NSG:      FullFeaturePhase,
		StatSN:   cmd.ExpStatSN,
		TaskTag:  cmd.TaskTag,
		ExpCmdSN: cmd.CmdSN,
		MaxCmdSN: cmd.CmdSN,
	}
	conn.resp.RawData = util.MarshalKVText(result)
	return nil
}

func iscsiExecNoopOut(conn *iscsiConnection) error {
	cmd := conn.req
	conn.resp = &ISCSICommand{
		OpCode:   OpNoopIn,
		Final:    true,
		NSG:      FullFeaturePhase,
		StatSN:   cmd.ExpStatSN,
		TaskTag:  cmd.TaskTag,
		ExpCmdSN: cmd.CmdSN + 1,
		MaxCmdSN: cmd.CmdSN + 10,
	}
	return nil
}

func iscsiExecTMFunction(conn *iscsiConnection) error {
	cmd := conn.req
	conn.resp = &ISCSICommand{
		OpCode:   OpSCSITaskResp,
		Final:    true,
		NSG:      FullFeaturePhase,
		StatSN:   cmd.ExpStatSN,
		TaskTag:  cmd.TaskTag,
		ExpCmdSN: cmd.CmdSN + 1,
		MaxCmdSN: cmd.CmdSN + 10,
	}
	return nil
}

func iscsiExecReject(conn *iscsiConnection) error {
	conn.resp = &ISCSICommand{
		OpCode: OpReject,
	}
	return nil
}

func (s *ISCSITargetService) txHandler(conn *iscsiConnection) {
	var (
		hdigest uint = 0
		ddigest uint = 0
		final   bool = false
	)
	if conn.state == CONN_STATE_SCSI {
		hdigest = conn.sessionParam[ISCSI_PARAM_HDRDGST_EN].Value & DIGEST_CRC32C
		ddigest = conn.sessionParam[ISCSI_PARAM_DATADGST_EN].Value & DIGEST_CRC32C
	}
	if conn.state == CONN_STATE_SCSI && conn.txTask == nil {
		err := s.scsiCommandHandler(conn)
		if err != nil {
			glog.Error(err)
			return
		}
	}
	for {
		switch conn.txIOState {
		case IOSTATE_TX_BHS:
			glog.V(2).Infof("ready to write response")
			glog.V(2).Infof("%s", conn.resp.String())
			glog.V(2).Infof("length of RawData is %d", len(conn.resp.RawData))
			glog.V(2).Infof("length of resp is %d", len(conn.resp.Bytes()))
			if l, err := conn.write(conn.resp.Bytes()); err != nil {
				debug.PrintStack()
				glog.Error(err)
				panic(err)
				return
			} else {
				conn.txIOState = IOSTATE_TX_INIT_AHS
				glog.V(2).Infof("success to write %d length", l)
			}
		case IOSTATE_TX_INIT_AHS:
			if hdigest != 0 {
				conn.txIOState = IOSTATE_TX_INIT_HDIGEST
			} else {
				conn.txIOState = IOSTATE_TX_INIT_DATA
			}
			if conn.txIOState != IOSTATE_TX_AHS {
				final = true
			}
		case IOSTATE_TX_AHS:
		case IOSTATE_TX_INIT_DATA:
			final = true
		case IOSTATE_TX_DATA:
			if ddigest != 0 {
				conn.txIOState = IOSTATE_TX_INIT_DDIGEST
			}
		default:
			glog.Errorf("error %d %d\n", conn.state, conn.txIOState)
			return
		}

		if final {
			break
		}
	}

	glog.V(3).Infof("connection state: %d", conn.state)
	switch conn.state {
	case CONN_STATE_CLOSE, CONN_STATE_EXIT:
		glog.Warningf("set connection to close")
		conn.state = CONN_STATE_CLOSE
	case CONN_STATE_SECURITY_LOGIN:
		conn.state = CONN_STATE_LOGIN
		glog.V(3).Infof("CONN_STATE_LOGIN")
	case CONN_STATE_SECURITY_FULL, CONN_STATE_LOGIN_FULL:
		if conn.sessionType == SESSION_NORMAL {
			conn.state = CONN_STATE_KERNEL
			glog.Infof("CONN_STATE_KERNEL")
			conn.state = CONN_STATE_SCSI
			glog.V(3).Infof("CONN_STATE_SCSI")
		} else {
			conn.state = CONN_STATE_FULL
			glog.V(3).Infof("CONN_STATE_FULL")
		}
		conn.rxIOState = IOSTATE_RX_BHS
		s.handler(DATAIN, conn)
	case CONN_STATE_SCSI:
		conn.txTask = nil
	default:
		glog.Warningf("unexpected connection state: %d", conn.state)
		conn.rxIOState = IOSTATE_RX_BHS
		s.handler(DATAIN, conn)
	}
	glog.Infof("%d", conn.state)
}

func (s *ISCSITargetService) scsiCommandHandler(conn *iscsiConnection) (err error) {
	req := conn.req
	switch req.OpCode {
	case OpSCSICmd:
		glog.V(2).Infof("SCSI Command processing...")
		scmd := &api.SCSICommand{}
		task := &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag, scmd: scmd}
		if req.Write {
			task.offset = req.DataLen
			task.r2tCount = int(req.ExpectedDataLen) - req.DataLen
			if !req.Final {
				task.unsolCount = 1
			}
			glog.V(2).Infof("SCSI write, R2T count: %d, unsol Count: %d, offset: %d", task.r2tCount, task.unsolCount, task.offset)

			if task.scmd.OutSDBBuffer.Buffer == nil {
				task.scmd.OutSDBBuffer.Buffer = bytes.NewBuffer([]byte{})
			}
			task.scmd.OutSDBBuffer.Buffer.Write(conn.req.RawData)
			if task.r2tCount > 0 {
				conn.session.ExpCmdSN += 1
				// prepare to receive more data
				task.state = taskPending
				conn.session.PendingTasks.Push(task)
				//conn.rxTask = nil
				conn.txTask = &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag, scmd: &api.SCSICommand{}}
				conn.txIOState = IOSTATE_TX_BHS
				conn.statSN += 1
				resp := &ISCSICommand{
					OpCode:        OpReady,
					Immediate:     true,
					Final:         true,
					StatSN:        req.ExpStatSN,
					TaskTag:       req.TaskTag,
					ExpCmdSN:      conn.session.ExpCmdSN,
					MaxCmdSN:      conn.session.ExpCmdSN + 10,
					R2TSN:         task.r2tSN,
					BufferOffset:  uint32(task.offset),
					DesiredLength: uint32(task.r2tCount),
				}
				if val := sessionKeys[ISCSI_PARAM_MAX_BURST].def; task.r2tCount > int(val) {
					resp.DesiredLength = uint32(val)
				}
				conn.resp = resp
				break
			}
		}
		task.offset = 0
		conn.rxTask = task
		if err = s.iscsiTaskQueueHandler(task); err != nil {
			return
		} else {
			conn.rxTask = nil
			conn.txTask = &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag, scmd: &api.SCSICommand{}}
			conn.txIOState = IOSTATE_TX_BHS
			conn.statSN += 1
			resp := &ISCSICommand{
				Immediate:    true,
				Final:        true,
				StatSN:       req.ExpStatSN,
				TaskTag:      req.TaskTag,
				ExpCmdSN:     conn.session.ExpCmdSN,
				MaxCmdSN:     conn.session.ExpCmdSN + 10,
				Status:       scmd.Result,
				SCSIResponse: 0x00,
				HasStatus:    true,
			}
			switch scmd.Direction {
			case api.SCSIDataRead:
				resp.OpCode = OpSCSIIn
				if scmd.InSDBBuffer.Buffer != nil {
					buf := scmd.InSDBBuffer.Buffer.Bytes()
					resp.RawData = buf
				} else {
					resp.RawData = []byte{}
				}
			case api.SCSIDataWrite:
				resp.OpCode = OpSCSIResp
				if scmd.InSDBBuffer.Buffer != nil {
					buf := scmd.InSDBBuffer.Buffer.Bytes()
					resp.RawData = buf
				} else {
					resp.RawData = []byte{}
				}
			case api.SCSIDataBidirection:
			case api.SCSIDataNone:
				resp.OpCode = OpSCSIResp
			}
			conn.resp = resp
		}
	case OpSCSITaskReq:
		// task management function
		conn.txTask = &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag, state: taskPending}
		conn.txIOState = IOSTATE_TX_BHS
		iscsiExecTMFunction(conn)
	case OpSCSIOut:
		glog.V(1).Infof("iSCSI Data-out processing...")
		var task *iscsiTask
		for _, t := range conn.session.PendingTasks {
			if t.tag == conn.req.TaskTag {
				task = t
			}
		}
		if task == nil {
			err = fmt.Errorf("Cannot find iSCSI task with tag[%v]", conn.req.TaskTag)
			glog.Error(err)
			return
		}
		task.offset = task.offset + conn.req.DataLen
		task.r2tCount = task.r2tCount - conn.req.DataLen
		task.scmd.OutSDBBuffer.Buffer.Write(conn.req.RawData)
		glog.V(2).Infof("Final: %v", conn.req.Final)
		glog.V(2).Infof("r2tCount: %v", task.r2tCount)
		if !conn.req.Final {
			glog.V(1).Infof("Not ready to exec the task")
			conn.rxIOState = IOSTATE_RX_BHS
			s.handler(DATAIN, conn)
			return nil
		} else if task.r2tCount > 0 {
			// prepare to receive more data
			conn.rxTask = nil
			conn.txTask = &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag, scmd: &api.SCSICommand{}}
			conn.txIOState = IOSTATE_TX_BHS
			conn.statSN += 1
			task.r2tSN += 1
			resp := &ISCSICommand{
				OpCode:        OpReady,
				Immediate:     true,
				Final:         true,
				StatSN:        req.ExpStatSN,
				TaskTag:       req.TaskTag,
				ExpCmdSN:      conn.session.ExpCmdSN,
				MaxCmdSN:      conn.session.ExpCmdSN + 10,
				R2TSN:         task.r2tSN,
				BufferOffset:  uint32(task.offset),
				DesiredLength: uint32(task.r2tCount),
			}
			if val := sessionKeys[ISCSI_PARAM_MAX_BURST].def; task.r2tCount > int(val) {
				resp.DesiredLength = uint32(val)
			}
			conn.resp = resp
			break
		}
		task.offset = 0
		glog.V(1).Infof("Process the Data-out package")
		conn.rxTask = task
		if err = s.iscsiExecTask(task); err != nil {
			return
		} else {
			conn.rxTask = nil
			conn.txTask = &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag, scmd: &api.SCSICommand{}, state: taskSCSI}
			conn.txIOState = IOSTATE_TX_BHS
			conn.statSN += 1
			resp := &ISCSICommand{
				OpCode:       OpSCSIResp,
				Immediate:    true,
				Final:        true,
				StatSN:       req.ExpStatSN,
				TaskTag:      req.TaskTag,
				ExpCmdSN:     conn.session.ExpCmdSN,
				MaxCmdSN:     conn.session.ExpCmdSN + 10,
				Status:       0,
				SCSIResponse: 0x00,
				HasStatus:    true,
			}
			conn.resp = resp
		}
	case OpNoopOut:
		conn.txTask = &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag}
		conn.txIOState = IOSTATE_TX_BHS
		iscsiExecNoopOut(conn)
	case OpLogoutReq:
		conn.txTask = &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag}
		conn.txIOState = IOSTATE_TX_BHS
		iscsiExecLogout(conn)
	case OpTextReq, OpSNACKReq:
		err = fmt.Errorf("Cannot handle yet %s", opCodeMap[conn.req.OpCode])
		glog.Error(err)
		return
	default:
		err = fmt.Errorf("Unknown op %s", opCodeMap[conn.req.OpCode])
		glog.Error(err)
		return
	}
	conn.rxIOState = IOSTATE_RX_BHS
	s.handler(DATAIN|DATAOUT, conn)
	return nil
}

func (s *ISCSITargetService) iscsiTaskQueueHandler(task *iscsiTask) error {
	conn := task.conn
	sess := conn.session
	cmd := task.cmd
	if cmd.Immediate {
		return s.iscsiExecTask(task)
	}
	cmdsn := cmd.CmdSN
	glog.V(2).Infof("CmdSN of command is %d, ExpCmdSN of session is %d", cmdsn, sess.ExpCmdSN)
	if cmdsn == sess.ExpCmdSN {
	retry:
		cmdsn += 1
		sess.ExpCmdSN = cmdsn
		glog.V(2).Infof("session's ExpCmdSN is %d", cmdsn)

		glog.V(2).Infof("process task(%d)", task.cmd.CmdSN)
		if err := s.iscsiExecTask(task); err != nil {
			glog.Error(err)
		}
		if len(sess.PendingTasks) == 0 {
			return nil
		}
		task = sess.PendingTasks.Pop().(*iscsiTask)
		cmd = task.cmd
		if cmd.CmdSN != cmdsn {
			sess.PendingTasks.Push(task)
			return nil
		}
		task.state = taskSCSI
		goto retry
	} else {
		if cmd.CmdSN < sess.ExpCmdSN {
			err := fmt.Errorf("unexpected cmd serial number: (%d, %d)", cmd.CmdSN, sess.ExpCmdSN)
			glog.Error(err)
			return err
		}
		glog.V(1).Infof("add task(%d) into task queue", task.cmd.CmdSN)
		// add this connection into queue and set this task as pending task
		task.state = taskPending
		sess.PendingTasks.Push(task)
		return fmt.Errorf("pending")
	}

	return nil
}

func (s *ISCSITargetService) iscsiExecTask(task *iscsiTask) error {
	cmd := task.cmd
	switch cmd.OpCode {
	case OpSCSICmd, OpSCSIOut:
		if cmd.Read {
			if cmd.Write {
				task.scmd.Direction = api.SCSIDataBidirection
			} else {
				task.scmd.Direction = api.SCSIDataRead
			}
		} else {
			if cmd.Write {
				task.scmd.Direction = api.SCSIDataWrite
			}
		}
		task.scmd.CommandITNID = task.conn.session.Tsih
		task.scmd.SCB = bytes.NewBuffer(cmd.CDB)
		task.scmd.SCBLength = len(cmd.CDB)
		task.scmd.Lun = cmd.LUN
		task.scmd.Tag = uint64(cmd.TaskTag)
		task.state = taskSCSI
		if task.scmd.OutSDBBuffer.Buffer == nil {
			task.scmd.OutSDBBuffer.Buffer = bytes.NewBuffer(cmd.RawData)
		}
		// add scsi target process queue
		err := s.SCSI.AddCommandQueue(task.conn.session.Target.SCSITarget.TID, task.scmd)
		if err != nil {
			task.state = 0
		}
		return err
	case OpLogoutReq:

	case OpNoopOut:
		// just do it in iscsi layer
	}
	return nil
}
