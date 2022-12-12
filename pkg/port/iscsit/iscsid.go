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
	"bufio"
	"container/list"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/config"
	"github.com/gostor/gotgt/pkg/scsi"
	"github.com/gostor/gotgt/pkg/util"
)

const (
	ISCSI_MAX_TSIH    = uint16(0xffff)
	ISCSI_UNSPEC_TSIH = uint16(0)
)

const (
	STATE_INIT = iota
	STATE_RUNNING
	STATE_SHUTTING_DOWN
	STATE_TERMINATE
)

var (
	EnableStats   bool
	CurrentHostIP string
	IPMutex       sync.Mutex
)

const (
	workChanNum  int    = 16
	bufSize      uint32 = 65536
	txMaxBufSize uint32 = (65536 + 48)
	//循环使用
	bufNum uint32 = 1024 //uint32(workChanNum * 8)
)

type ISCSITargetDriver struct {
	SCSI                   *scsi.SCSITargetService
	Name                   string
	iSCSITargets           map[string]*ISCSITarget
	TSIHPool               map[uint16]bool
	TSIHPoolMutex          sync.Mutex
	isClientConnected      bool
	enableStats            bool
	mu                     *sync.RWMutex
	l                      net.Listener
	state                  uint8
	OpCode                 int
	TargetStats            scsi.Stats
	clusterIP              string
	blockMultipleHostLogin bool

	workChan     chan *iscsiTask
	stopChan     chan struct{}
	cmdStopChan  chan struct{}
	workScmdChan chan *iscsiTask
}

func init() {
	scsi.RegisterTargetDriver(iSCSIDriverName, NewISCSITargetDriver)
}

func NewISCSITargetDriver(base *scsi.SCSITargetService) (scsi.SCSITargetDriver, error) {
	driver := &ISCSITargetDriver{
		Name:         iSCSIDriverName,
		iSCSITargets: map[string]*ISCSITarget{},
		SCSI:         base,
		TSIHPool:     map[uint16]bool{0: true, 65535: true},
		mu:           &sync.RWMutex{},
	}

	driver.workChan = make(chan *iscsiTask, workChanNum)
	driver.workScmdChan = make(chan *iscsiTask, workChanNum)
	driver.stopChan = make(chan struct{})

	if EnableStats {
		driver.enableStats = true
		driver.TargetStats.SCSIIOCount = map[int]int64{}
	}
	go driver.iscsiTaskQueueRoutineHandler()
	go driver.iscsiTaskQueueRoutine()

	return driver, nil
}

func (s *ISCSITargetDriver) AllocTSIH() uint16 {
	var i uint16
	s.TSIHPoolMutex.Lock()
	for i = uint16(0); i < ISCSI_MAX_TSIH; i++ {
		exist := s.TSIHPool[i]
		if !exist {
			s.TSIHPool[i] = true
			s.TSIHPoolMutex.Unlock()
			return i
		}
	}
	s.TSIHPoolMutex.Unlock()
	return ISCSI_UNSPEC_TSIH
}

func (s *ISCSITargetDriver) ReleaseTSIH(tsih uint16) {
	s.TSIHPoolMutex.Lock()
	delete(s.TSIHPool, tsih)
	s.TSIHPoolMutex.Unlock()
}

func (s *ISCSITargetDriver) NewTarget(tgtName string, configInfo *config.Config) error {
	if _, ok := s.iSCSITargets[tgtName]; ok {
		return fmt.Errorf("target name has been existed")
	}
	stgt, err := s.SCSI.NewSCSITarget(len(s.iSCSITargets), "iscsi", tgtName)
	if err != nil {
		return err
	}
	tgt := newISCSITarget(stgt)
	s.iSCSITargets[tgtName] = tgt
	scsiTPG := tgt.SCSITarget.TargetPortGroups[0]
	targetConfig := configInfo.ISCSITargets[tgtName]
	for tpgt, portalIDArrary := range targetConfig.TPGTs {
		tpgtNumber, _ := strconv.ParseUint(tpgt, 10, 16)
		tgt.TPGTs[uint16(tpgtNumber)] = &iSCSITPGT{uint16(tpgtNumber), make(map[string]struct{})}
		targetPortName := fmt.Sprintf("%s,t,0x%02x", tgtName, tpgtNumber)
		scsiTPG.TargetPortGroup = append(scsiTPG.TargetPortGroup, &api.SCSITargetPort{uint16(tpgtNumber), targetPortName})
		for _, portalID := range portalIDArrary {
			portal := configInfo.ISCSIPortals[portalID]
			s.AddiSCSIPortal(tgtName, uint16(tpgtNumber), portal.Portal)
		}
	}
	return nil
}

func (s *ISCSITargetDriver) SetClusterIP(ip string) {
	s.clusterIP = ip
}

func (s *ISCSITargetDriver) EnableBlockMultipleHostLogin() {
	s.blockMultipleHostLogin = true
}

func (s *ISCSITargetDriver) RereadTargetLUNMap() {
	s.SCSI.RereadTargetLUNMap()
}

func (s *ISCSITargetDriver) AddiSCSIPortal(tgtName string, tpgt uint16, portal string) error {
	var (
		ok       bool
		target   *ISCSITarget
		tpgtInfo *iSCSITPGT
	)

	if target, ok = s.iSCSITargets[tgtName]; !ok {
		return fmt.Errorf("No such target: %s", tgtName)
	}

	if tpgtInfo, ok = target.TPGTs[tpgt]; !ok {
		return fmt.Errorf("No such TPGT: %d", tpgt)
	}
	tgtPortals := tpgtInfo.Portals

	if _, ok = tgtPortals[portal]; !ok {
		tgtPortals[portal] = struct{}{}
	} else {
		return fmt.Errorf("duplicate portal %s,in %s,%d", portal, tgtName, tpgt)
	}

	return nil
}

func (s *ISCSITargetDriver) HasPortal(tgtName string, tpgt uint16, portal string) bool {
	var (
		ok       bool
		target   *ISCSITarget
		tpgtInfo *iSCSITPGT
	)

	if target, ok = s.iSCSITargets[tgtName]; !ok {
		return false
	}
	if tpgtInfo, ok = target.TPGTs[tpgt]; !ok {
		return false
	}
	tgtPortals := tpgtInfo.Portals

	if _, ok = tgtPortals[portal]; !ok {
		return false
	} else {
		return true
	}
}

func (s *ISCSITargetDriver) Run(port int) error {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	s.mu.Lock()
	s.l = l
	s.mu.Unlock()
	log.Infof("iSCSI service listening on: %v", s.l.Addr())

	s.setState(STATE_RUNNING)
	for {
		conn, err := l.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok {
				if !err.Temporary() {
					log.Warning("Closing connection with initiator...")
					break
				}
			}
			log.Error(err)
			continue
		}

		remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

		IPMutex.Lock()
		if CurrentHostIP == "" {
			CurrentHostIP = remoteIP
		}
		IPMutex.Unlock()

		if s.blockMultipleHostLogin && remoteIP != CurrentHostIP {
			conn.Close()
			log.Infof("rejecting connection: %s target already connected at %s",
				remoteIP, CurrentHostIP)
			continue
		}

		log.Info("connection establishing at: ", conn.LocalAddr().String())
		s.setClientStatus(true)

		iscsiConn := &iscsiConnection{conn: conn,
			loginParam: &iscsiLoginParam{}}

		iscsiConn.init()
		log.Infof("Target is connected to initiator: %s", conn.RemoteAddr().String())
		// start a new thread to do with this command
		go s.handler(DATAIN, iscsiConn)
	}
	return nil
}

func (s *ISCSITargetDriver) setClientStatus(ok bool) {
	s.isClientConnected = ok
}

func (s *ISCSITargetDriver) isInitiatorConnected() bool {
	return s.isClientConnected
}
func (s *ISCSITargetDriver) Close() error {
	s.mu.Lock()
	l := s.l
	s.setClientStatus(false)
	s.mu.Unlock()
	if l != nil {
		s.setState(STATE_SHUTTING_DOWN)
		if err := l.Close(); err != nil {
			return err
		}
		s.setState(STATE_TERMINATE)
		return nil
	}
	return nil
}

func (s *ISCSITargetDriver) setState(st uint8) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = st
}

func (s *ISCSITargetDriver) Resize(size uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.SCSI.Resize(size)
}

func initBufPool(conn *iscsiConnection) {

	conn.bufPoolMap = make(map[uint32]bool, bufNum)

	for i := uint32(0); i < uint32(bufNum); i++ {
		conn.bufPool[i] = make([]byte, bufSize)
		conn.bufPoolMap[i] = false
	}
}

func releasBufPool(conn *iscsiConnection) {
	for addr := range conn.bufPoolMap {
		delete(conn.bufPoolMap, addr)
	}
}

func staticsBufPool(conn *iscsiConnection) uint32 {
	var used uint32 = 0
	conn.poolLock.Lock()
	for _, m := range conn.bufPoolMap {
		if m == true {
			used++
		}
	}
	conn.poolLock.Unlock()

	return used
}

func getBufPool(conn *iscsiConnection, size uint32) []byte {
	if size == 0 {
		return []byte{}
	}

	if size > bufSize {
		return make([]byte, int(size))
	}

	for {
		conn.poolLock.Lock()
		for addr, m := range conn.bufPoolMap {
			if m == false {
				conn.bufPoolMap[addr] = true
				conn.poolLock.Unlock()
				return conn.bufPool[addr][0:size]
			}
		}

		conn.poolLock.Unlock()
		time.Sleep(10 * time.Millisecond)
		log.Info("wait buf pool")
	}

	return nil
}

func freeRxBufList(conn *iscsiConnection, l *list.List) {
	if l == nil {
		log.Error("freeRxBufList nil")
		return
	}

	for e := l.Front(); e != nil; e = l.Front() {
		l.Remove(e)
		//		atomic.AddUint32(&conn.rxIoSeqRecycle, 1)
		b, ok := e.Value.([]byte)
		if ok {
			freeBufPool(conn, b)
		}
	}
}

func freeBufPool(conn *iscsiConnection, buf []byte) {
	if len(buf) == 0 || uint32(len(buf)) > bufSize {
		return
	}

	//这种遍历对比地址方式效率较低，可优化，但需要暴露更多内部信息?比如id
	//直接用 &[]byte作为map key ?，不可行，因为切片是包含len&cap, 改变len， 则切片不一致
	for i, m := range conn.bufPool {
		if &buf[0] == &m[0] {
			conn.poolLock.Lock()
			conn.bufPoolMap[uint32(i)] = false
			conn.poolLock.Unlock()
			return
		}
	}

	return
}

func (s *ISCSITargetDriver) handler(events byte, conn *iscsiConnection) {

	const rxBufNum = 1024

	//由于cmd 会一直引用 rxHeadBuf, 所以数量先加大
	var rxHeadBuf [rxBufNum][]byte

	ioSeq := uint32(0)
	for i := 0; i < int(rxBufNum); i++ {
		rxHeadBuf[i] = make([]byte, BHS_SIZE)
	}

	initBufPool(conn)
	txStopChan := make(chan struct{})
	cmdStopChan := make(chan struct{})
	conn.txWorkChan = make(chan *SendPackage, workChanNum)
	conn.txWorkBufChan = make(chan []byte, workChanNum)

	go s.txHandlerWrite(conn, txStopChan)
	go s.scsiCommandChanHandler(conn, cmdStopChan)
	//读写分离
	for {
		err := s.rxHandler(conn, rxHeadBuf[ioSeq%rxBufNum])
		if err != nil {
			break
		}
		ioSeq++
	}

	close(txStopChan)
	close(cmdStopChan)
	close(conn.txWorkChan)
	close(conn.txWorkBufChan)

	releasBufPool(conn)
	log.Warningf("iscsi connection[%d] closed", conn.cid)
	conn.close()
}

func (s *ISCSITargetDriver) rxHandler(conn *iscsiConnection, rxbuf []byte) error { //, buf []byte) error {
	var (
		cmd    *ISCSICommand
		length int
		err    error
	)
	length, err = conn.readData(rxbuf)
	if err != nil {
		if err != io.EOF {
			log.Error(err)
		}
		return err
	}

	if length == 0 {
		log.Warningf("set connection to close")
		conn.state = CONN_STATE_CLOSE
		return err
	}

	cmd, err = parseHeader(rxbuf)
	if err != nil {
		log.Error(err)
		log.Warningf("set connection to close")
		conn.state = CONN_STATE_CLOSE
		return err
	}

	//if length == BHS_SIZE && cmd.DataLen != 0 {
	if cmd.DataLen != 0 {

		dl := ((cmd.DataLen + DataPadding - 1) / DataPadding) * DataPadding
		if dl <= int(bufSize) {
			cmd.RawData = getBufPool(conn, uint32(dl))
		} else {
			cmd.RawData = make([]byte, int(dl))
		}

		_, err := conn.readData(cmd.RawData[0:])
		if err != nil {
			log.Error(err)
			return err
		}
	}

	conn.req = cmd
	if conn.state == CONN_STATE_SCSI {
		//		log.Debugf("read buf command %x ", conn.req.TaskTag)
		//分开处理, 性能更佳，具体后续再对应环境测试
		if cmd.Read {
			conn.scsiCmdChan <- cmd
		} else {
			s.scsiCommandHandler(conn, cmd)
		}

	} else {
		var resp *ISCSICommand
		var err error
		switch cmd.OpCode {
		case OpLoginReq:
			log.Debugf("OpLoginReq")
			resp, err = s.iscsiExecLogin(conn, cmd)
			if err != nil {
				log.Error(err)
				log.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
			}
		case OpLogoutReq:
			log.Debug("OpLogoutReq")
			s.setClientStatus(false)
			resp, err = iscsiExecLogout(conn, cmd)
			if err != nil {
				log.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
			}
		case OpTextReq:
			log.Debug("OpTextReq")
			resp, err = s.iscsiExecText(conn, cmd)
			if err != nil {
				log.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
			}
		default:
			resp, err = iscsiExecReject(conn, cmd)
		}

		freeBufPool(conn, cmd.RawData)
		log.Debugf("connection state is %v", conn.State())
		//需要发送的数据放给OUT线程
		s.txHandler(conn, resp)
	}

	return nil
}

func (s *ISCSITargetDriver) iscsiExecLogin(conn *iscsiConnection, cmd *ISCSICommand) (*ISCSICommand, error) {

	conn.cid = cmd.ConnID
	conn.loginParam.iniCSG = cmd.CSG
	conn.loginParam.iniNSG = cmd.NSG
	conn.loginParam.iniCont = cmd.Cont
	conn.loginParam.iniTrans = cmd.Transit
	conn.loginParam.isid = cmd.ISID
	conn.loginParam.tsih = cmd.TSIH
	conn.expCmdSN = cmd.CmdSN
	conn.maxBurstLength = MaxBurstLength
	conn.maxRecvDataSegmentLength = MaxRecvDataSegmentLength
	conn.maxSeqCount = conn.maxBurstLength / conn.maxRecvDataSegmentLength

	if conn.loginParam.iniCSG == SecurityNegotiation {
		if err := conn.processSecurityData(); err != nil {
			return nil, err
		}
		conn.state = CONN_STATE_LOGIN
		return conn.buildRespPackage(OpLoginResp, nil, cmd)
	}

	if _, err := conn.processLoginData(cmd); err != nil {
		return nil, err
	}

	if !conn.loginParam.paramInit {
		if err := s.BindISCSISession(conn); err != nil {
			conn.state = CONN_STATE_EXIT
			return nil, err
		}
		conn.loginParam.paramInit = true
	}
	if conn.loginParam.tgtNSG == FullFeaturePhase &&
		conn.loginParam.tgtTrans {
		conn.state = CONN_STATE_LOGIN_FULL
	} else {
		conn.state = CONN_STATE_LOGIN
	}

	return conn.buildRespPackage(OpLoginResp, nil, cmd)
}

func iscsiExecLogout(conn *iscsiConnection, cmd *ISCSICommand) (*ISCSICommand, error) {
	log.Infof("Logout request received from initiator: %v", conn.conn.RemoteAddr().String())
	resp := &ISCSICommand{
		OpCode:  OpLogoutResp,
		StatSN:  cmd.ExpStatSN,
		TaskTag: cmd.TaskTag,
	}
	if conn.session == nil {
		resp.ExpCmdSN = cmd.CmdSN
		resp.MaxCmdSN = cmd.CmdSN
	} else {
		resp.ExpCmdSN = conn.session.ExpCmdSN
		resp.MaxCmdSN = conn.session.ExpCmdSN + conn.session.MaxQueueCommand
	}
	IPMutex.Lock()
	remoteIP := strings.Split(conn.conn.RemoteAddr().String(), ":")[0]
	if CurrentHostIP == remoteIP {
		CurrentHostIP = ""
	}
	IPMutex.Unlock()
	return resp, nil
}

func (s *ISCSITargetDriver) iscsiExecText(conn *iscsiConnection, cmd *ISCSICommand) (*ISCSICommand, error) {
	var result = []util.KeyValue{}
	keys := util.ParseKVText(cmd.RawData)
	if st, ok := keys["SendTargets"]; ok {
		if st == "All" {
			for name, tgt := range s.iSCSITargets {
				log.Debugf("iscsi target: %v", name)
				//log.Debugf("iscsi target portals: %v", tgt.Portals)

				result = append(result, util.KeyValue{
					Key:   "TargetName",
					Value: name,
				})
				if s.clusterIP == "" {
					for _, tpgt := range tgt.TPGTs {
						for portal := range tpgt.Portals {
							targetPort := fmt.Sprintf("%s,%d", portal, tpgt.TPGT)
							result = append(result, util.KeyValue{
								Key:   "TargetAddress",
								Value: targetPort,
							})
						}
					}
				} else {
					for _, tpgt := range tgt.TPGTs {
						targetPort := fmt.Sprintf("%s,%d", s.clusterIP, tpgt.TPGT)
						result = append(result, util.KeyValue{
							Key:   "TargetAddress",
							Value: targetPort,
						})
					}
				}
			}
		}
	}

	resp := &ISCSICommand{
		OpCode:   OpTextResp,
		Final:    true,
		NSG:      FullFeaturePhase,
		StatSN:   cmd.ExpStatSN,
		TaskTag:  cmd.TaskTag,
		ExpCmdSN: cmd.CmdSN,
		MaxCmdSN: cmd.CmdSN,
	}
	resp.RawData = util.MarshalKVText(result)
	return resp, nil
}

func iscsiExecNoopOut(conn *iscsiConnection, cmd *ISCSICommand) (*ISCSICommand, error) {
	return conn.buildRespPackage(OpNoopIn, nil, cmd)
}

func iscsiExecReject(conn *iscsiConnection, cmd *ISCSICommand) (*ISCSICommand, error) {
	return conn.buildRespPackage(OpReject, nil, cmd)
}

func iscsiExecR2T(conn *iscsiConnection, task *iscsiTask) (*ISCSICommand, error) {
	return conn.buildRespPackage(OpReady, task, nil)
}

func (s *ISCSITargetDriver) txHandlerWrite(conn *iscsiConnection, txStopChan chan struct{}) {

	writer := bufio.NewWriterSize(conn.conn, int(txMaxBufSize))

	//	ticker := time.NewTicker(time.Millisecond * 5000)
	//	defer ticker.Stop()

	for {
		select {
		//		case <-ticker.C:
		//log.Infof("statics bufPool used  %d  ", staticsBufPool(conn))

		case buf := <-conn.txWorkBufChan:
			if l, err := conn.write(buf); err != nil {
				log.Errorf("failed to write data to client: %v", err)
				return
			} else {
				log.Debugf("success to write %d length", l)
			}
		case sp := <-conn.txWorkChan:

			if sp == nil {
				return
			}

			if l, err := writer.Write(sp.headBuf); err != nil {
				log.Errorf("failed to write head to client: %v", err)
				return
			} else {
				log.Debugf("success to write header %d length", l)
			}

			if l, err := writer.Write(sp.dataBuf); err != nil {
				log.Errorf("failed to write data to client: %v", err)
				return
			} else {
				log.Debugf("success to write data %d length", l)
			}

			padding := DataPadding - len(sp.dataBuf)%DataPadding
			if padding < DataPadding {
				for i := 0; i < padding; i++ {
					writer.Write([]byte{0})
				}
			}

			if err := writer.Flush(); err != nil {
				log.Errorf("failed to flush  to client: %v", err)
				return
			} else {
				log.Debugf("success to write flush ")
			}
			freeBufPool(conn, sp.dataBuf)
			continue
		case <-txStopChan:
			//log.Info("txHandlerWrite exit ")
			return
		}
	}
}

func (s *ISCSITargetDriver) txHandler(conn *iscsiConnection, resp *ISCSICommand) {
	log.Debug("enter txhander ")

	if resp == nil {
		return
	}
	log.Debugf("enter txHander resp.Task %x ", resp.TaskTag)
	var (
		hdigest uint   = 0
		ddigest uint   = 0
		offset  uint32 = 0
		final   bool   = false
		count   uint32 = 0
	)
	if conn.state == CONN_STATE_SCSI {
		hdigest = conn.loginParam.sessionParam[ISCSI_PARAM_HDRDGST_EN].Value & DIGEST_CRC32C
		ddigest = conn.loginParam.sessionParam[ISCSI_PARAM_DATADGST_EN].Value & DIGEST_CRC32C
	}
	segmentLen := conn.maxRecvDataSegmentLength
	transferLen := len(resp.RawData)
	resp.DataSN = 0
	maxCount := conn.maxSeqCount
	txIOState := IOSTATE_TX_BHS

	if s.enableStats {
		if resp.OpCode == OpSCSIResp || resp.OpCode == OpSCSIIn {
			s.UpdateStats(conn, resp)
		}
	}

	/* send data splitted by segmentLen */
SendRemainingData:
	//	log.Debugf("transferLen %v, offset %v , segmentLen %v ", transferLen, offset, segmentLen)
	if resp.OpCode == OpSCSIIn {
		resp.BufferOffset = offset
		if int(offset+segmentLen) < transferLen {
			count += 1
			if count < maxCount {
				resp.FinalInSeq = false
				resp.Final = false
			} else {
				count = 0
				resp.FinalInSeq = true
				resp.Final = false
			}
			offset = offset + segmentLen
			resp.DataLen = int(segmentLen)
		} else {
			resp.FinalInSeq = true
			resp.Final = true
			resp.DataLen = transferLen - int(offset)
		}
	}
	for {
		switch txIOState {
		case IOSTATE_TX_BHS:
			if resp.OpCode == OpSCSIIn {
				sp := &SendPackage{headBuf: resp.Bytes(), dataBuf: resp.RawData[resp.BufferOffset : resp.BufferOffset+uint32(resp.DataLen)]}
				conn.txWorkChan <- sp // resp.Bytes(buf)
			} else {
				conn.txWorkBufChan <- resp.Bytes()
				freeBufPool(conn, resp.RawData)
			}

			if hdigest != 0 {
				txIOState = IOSTATE_TX_INIT_HDIGEST
			} else {
				txIOState = IOSTATE_TX_INIT_DATA
			}
			if txIOState != IOSTATE_TX_AHS {
				final = true
			}
		case IOSTATE_TX_AHS:
		case IOSTATE_TX_INIT_DATA:
			final = true
		case IOSTATE_TX_DATA:
			if ddigest != 0 {
				txIOState = IOSTATE_TX_INIT_DDIGEST
			}
		default:
			log.Errorf("error %d %d\n", conn.state, txIOState)
			return
		}

		if final {
			if resp.OpCode == OpSCSIIn && resp.Final != true {
				resp.DataSN++
				txIOState = IOSTATE_TX_BHS
				goto SendRemainingData
			} else {
				break
			}
		}
	}

	log.Debugf("connection state: %v", conn.State())
	switch conn.state {
	case CONN_STATE_CLOSE, CONN_STATE_EXIT:
		conn.state = CONN_STATE_CLOSE
	case CONN_STATE_SECURITY_LOGIN:
		conn.state = CONN_STATE_LOGIN
	case CONN_STATE_LOGIN:
	case CONN_STATE_SECURITY_FULL, CONN_STATE_LOGIN_FULL:
		if conn.session.SessionType == SESSION_NORMAL {
			conn.state = CONN_STATE_KERNEL
			conn.state = CONN_STATE_SCSI
		} else {
			conn.state = CONN_STATE_FULL
		}
	case CONN_STATE_SCSI:
	default:
		log.Warnf("unexpected connection state: %v", conn.State())
	}
}

func (s *ISCSITargetDriver) scsiCommandChanHandler(conn *iscsiConnection, stopChan chan struct{}) {
	for {
		select {
		case cmd := <-conn.scsiCmdChan:
			s.scsiCommandHandler(conn, cmd)
			continue
		case <-stopChan:
			log.Debug("scsiCommandChanHandler exit ")
			return
		}
	}
}

func (s *ISCSITargetDriver) scsiCommandHandler(conn *iscsiConnection, cmd *ISCSICommand) (err error) {
	var resp *ISCSICommand
	req := cmd
	switch req.OpCode {
	case OpSCSICmd:
		log.Debugf("SCSI Command tag:0x%x, CmdSN:%d processing...", req.TaskTag, req.CmdSN)
		conn.readLock.Lock()
		scmd := &api.SCSICommand{
			ITNexusID:       conn.session.ITNexus.ID,
			SCB:             req.CDB,
			SCBLength:       len(req.CDB),
			Lun:             req.LUN,
			Tag:             uint64(req.TaskTag),
			RelTargetPortID: conn.session.TPGT,
		}
		conn.readLock.Unlock()
		if req.Read {
			if req.Write {
				scmd.Direction = api.SCSIDataBidirection
			} else {
				scmd.Direction = api.SCSIDataRead
			}
		} else {
			if req.Write {
				scmd.Direction = api.SCSIDataWrite
			}
		}

		task := &iscsiTask{conn: conn, cmd: req, tag: req.TaskTag, scmd: scmd}
		task.scmd.OpCode = req.SCSIOpCode
		if scmd.Direction == api.SCSIDataBidirection {
			task.scmd.Result = api.SAMStatCheckCondition.Stat
			scsi.BuildSenseData(task.scmd, scsi.ILLEGAL_REQUEST, scsi.NO_ADDITIONAL_SENSE)
			conn.buildRespPackage(OpSCSIResp, task, nil)
			break
		}
		if req.Write {
			log.Debugf("scsiCommandHandler: len(req.RawData)=%d, ExpectedDataLen=%d, req.DataLen=%d", len(req.RawData), req.ExpectedDataLen, req.DataLen)
			task.r2tCount = int(req.ExpectedDataLen) - req.DataLen
			task.expectedDataLength = int64(req.ExpectedDataLen)
			if !req.Final {
				task.unsolCount = 1
			}
			// new buffer for the data out
			if scmd.OutSDBBuffer == nil {
				blen := int(req.ExpectedDataLen)
				if blen == 0 {
					blen = int(req.DataLen)
				}
				scmd.OutSDBBuffer = &api.SCSIDataBufferList{
					Length:     uint32(blen),
					BufferList: list.New(),
				}
			}
			log.Debugf("SCSI write, R2T count: %d, unsol Count: %d, offset: %d", task.r2tCount, task.unsolCount, task.offset)

			if conn.session.SessionParam[ISCSI_PARAM_IMM_DATA_EN].Value == 1 {
				log.Debugf("push data into scmd.OutSDBBuffer.BufferList")
				scmd.OutSDBBuffer.BufferList.PushBack(req.RawData)
				task.offset += req.DataLen
			}
			if task.r2tCount > 0 {
				// prepare to receive more data
				//conn.session.ExpCmdSN += 1
				task.state = taskPending
				conn.session.PendingTasksMutex.Lock()
				conn.session.PendingTasks.Push(task)
				conn.session.PendingTasksMutex.Unlock()
				if conn.session.SessionParam[ISCSI_PARAM_INITIAL_R2T_EN].Value == 1 {
					resp, err := iscsiExecR2T(conn, task)
					if err != nil {
						log.Error("iscsiExeR2T error")
					} else {
						s.txHandler(conn, resp)
					}
					return nil
				} else {
					log.Debugf("Not ready to exec the task")
					return nil
				}
			}
		} else if scmd.InSDBBuffer == nil {
			buf := getBufPool(conn, req.ExpectedDataLen)
			scmd.InSDBBuffer = &api.SCSIDataBuffer{
				Length: uint32(req.ExpectedDataLen),
				Buffer: buf,
			}
		}
		task.offset = 0
		s.workChan <- task
		log.Debugf("send workchan task.Tag %x ", task.tag)
		return
	case OpSCSITaskReq:
		// task management function
		task := &iscsiTask{conn: conn, cmd: req, tag: req.TaskTag, scmd: nil}
		s.workChan <- task
	case OpSCSIOut:
		log.Debugf("iSCSI Data-out processing...")
		conn.session.PendingTasksMutex.RLock()
		task := conn.session.PendingTasks.GetByTag(req.TaskTag)
		conn.session.PendingTasksMutex.RUnlock()
		if task == nil {
			err = fmt.Errorf("Cannot find iSCSI task with tag[%v]", req.TaskTag)
			log.Error(err)
			return err
		}
		task.scmd.OutSDBBuffer.BufferList.PushBack(req.RawData)
		task.offset += req.DataLen
		task.r2tCount = task.r2tCount - req.DataLen
		log.Debugf("Final: %v", req.Final)
		log.Debugf("r2tCount: %v", task.r2tCount)
		if !req.Final {
			log.Debugf("Not ready to exec the task")
			return nil
		} else if task.r2tCount > 0 {
			// prepare to receive more data
			if task.unsolCount == 0 {
				task.r2tSN += 1
			} else {
				task.r2tSN = 0
				task.unsolCount = 0
			}
			resp, err = iscsiExecR2T(conn, task)
			break
		} else {
			log.Debugf("Process the Data-out package")
			conn.session.PendingTasksMutex.Lock()
			conn.session.PendingTasks.RemoveByTag(req.TaskTag)
			conn.session.PendingTasksMutex.Unlock()
			s.workChan <- task
		}
	case OpNoopOut:
		resp, err = iscsiExecNoopOut(conn, cmd)
	case OpLogoutReq:
		s.setClientStatus(false)
		resp, err = iscsiExecLogout(conn, cmd)
	case OpTextReq, OpSNACKReq:
		err = fmt.Errorf("Cannot handle yet %s", opCodeMap[req.OpCode])
		log.Error(err)
		return
	default:
		err = fmt.Errorf("Unknown op %s", opCodeMap[req.OpCode])
		log.Error(err)
		return
	}
	s.txHandler(conn, resp)
	return nil
}

func (s *ISCSITargetDriver) iscsiTaskQueueRoutineHandler() {
	var wg sync.WaitGroup

	for i := 0; i < workChanNum; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case task := <-s.workScmdChan:
					var resp *ISCSICommand

					scmd := task.scmd
					if scmd == nil {
						resp, _ = task.conn.buildRespPackage(OpSCSITaskResp, task, nil)
					} else if scmd.Direction == api.SCSIDataRead &&
						scmd.SenseBuffer == nil &&
						task.cmd != nil &&
						task.cmd.ExpectedDataLen != 0 {
						resp, _ = task.conn.buildRespPackage(OpSCSIIn, task, nil)
					} else {
						resp, _ = task.conn.buildRespPackage(OpSCSIResp, task, nil)
					}

					s.txHandler(task.conn, resp)
					if scmd != nil && scmd.OutSDBBuffer != nil {
						freeRxBufList(task.conn, scmd.OutSDBBuffer.BufferList)
					}
					continue

				case <-s.stopChan:
					log.Debug("writer scmd work exit")
					return
				}
			}
		}(i)
	}

	wg.Wait()
}

func (s *ISCSITargetDriver) iscsiTaskQueueRoutine() {
	var wg sync.WaitGroup

	for i := 0; i < workChanNum; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for {
				select {
				case task := <-s.workChan:
					log.Debugf("go routine work task Tag:0x%x, CmdSN:%d, StatSN:%d, R2T:%d", task.tag, task.cmd.CmdSN, task.cmd.StatSN, task.r2tCount)
					err := s.iscsiTaskQueueHandler(task)
					if err != nil {
						log.Errorf("TaskiscsiTaskQueueHandler error, %v", err)
						return
					}

					s.workScmdChan <- task
					continue
				case <-s.stopChan:
					log.Debug("writer task work exit")
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func (s *ISCSITargetDriver) iscsiTaskQueueHandler(task *iscsiTask) error {
	conn := task.conn
	sess := conn.session
	cmd := task.cmd
	if cmd.Immediate {
		_, err := s.iscsiExecTask(task)
		return err
	}
	cmdsn := cmd.CmdSN
	log.Debugf("CmdSN of command is %d", cmdsn)
	if cmdsn == sess.ExpCmdSN {
	retry:
		cmdsn += 1
		sess.ExpCmdSN = cmdsn
		log.Debugf("session's ExpCmdSN is %d", cmdsn)

		log.Debugf("process task(%d)", task.cmd.CmdSN)
		if _, err := s.iscsiExecTask(task); err != nil {
			log.Error(err)
		}
		sess.PendingTasksMutex.Lock()
		if sess.PendingTasks.Len() == 0 {
			sess.PendingTasksMutex.Unlock()
			return nil
		}
		task = sess.PendingTasks.Pop()
		cmd = task.cmd
		if cmd.CmdSN != cmdsn {
			log.Debugf("cmd.CmdSN(%d) != cmdsn(%d)", cmd.CmdSN, cmdsn)
			sess.PendingTasks.Push(task)
			sess.PendingTasksMutex.Unlock()
			return nil
		}
		task.state = taskSCSI
		sess.PendingTasksMutex.Unlock()
		goto retry
	} else {
		if cmd.CmdSN < sess.ExpCmdSN {
			err := fmt.Errorf("unexpected cmd serial number: (%d, %d)", cmd.CmdSN, sess.ExpCmdSN)
			log.Warn(err)
			return err
		}
		if cmd.CmdSN > sess.MaxCmdSN {
			err := fmt.Errorf("unexpected cmd serial number(%d), bigger than MaxCmdSN(%d) ", cmd.CmdSN, sess.MaxCmdSN)
			log.Warn(err)
			return err
		}
		log.Debugf("add task(%d) into task queue, CmdSN=%d, ExpCmdSN=%d", task.tag, task.cmd.CmdSN, sess.ExpCmdSN)
		// add this task into queue and set it as a pending task
		sess.PendingTasksMutex.Lock()
		task.state = taskPending
		sess.PendingTasks.Push(task)
		sess.PendingTasksMutex.Unlock()
		//return fmt.Errorf("pending")
	}

	return nil
}

func (s *ISCSITargetDriver) iscsiExecTask(task *iscsiTask) (*ISCSICommand, error) {
	cmd := task.cmd
	switch cmd.OpCode {
	case OpSCSICmd, OpSCSIOut:
		task.state = taskSCSI
		// add scsi target process queue
		err := s.SCSI.AddCommandQueue(task.conn.session.Target.SCSITarget.TID, task.scmd)
		if err != nil {
			task.state = 0
		}
		return nil, err
	case OpLogoutReq:

	case OpNoopOut:
		// just do it in iscsi layer
	case OpSCSITaskReq:
		sess := task.conn.session
		switch cmd.TaskFunc {
		case ISCSI_TM_FUNC_ABORT_TASK:
			log.Debugf("ISCSI_TM_FUNC_ABORT_TASK")
			sess.PendingTasksMutex.Lock()
			stask := sess.PendingTasks.RemoveByTag(cmd.ReferencedTaskTag)
			sess.PendingTasksMutex.Unlock()
			if stask == nil {
				log.Debugf("stask is nil")
				task.result = ISCSI_TMF_RSP_NO_TASK
			} else {
				// abort this task
				log.Debugf("abort the task[%v]", stask.tag)
				if stask.scmd == nil {
					stask.scmd = &api.SCSICommand{Result: api.SAM_STAT_TASK_ABORTED}
				}
				stask.conn = task.conn
				log.Debugf("stask.conn: %#v", stask.conn)
				stask.conn.buildRespPackage(OpSCSIResp, stask, nil)
				task.result = ISCSI_TMF_RSP_COMPLETE
			}
		case ISCSI_TM_FUNC_ABORT_TASK_SET:
		case ISCSI_TM_FUNC_LOGICAL_UNIT_RESET:
		case ISCSI_TM_FUNC_CLEAR_ACA:
			fallthrough
		case ISCSI_TM_FUNC_CLEAR_TASK_SET:
			fallthrough
		case ISCSI_TM_FUNC_TARGET_WARM_RESET, ISCSI_TM_FUNC_TARGET_COLD_RESET, ISCSI_TM_FUNC_TASK_REASSIGN:
			task.result = ISCSI_TMF_RSP_NOT_SUPPORTED
		default:
			task.result = ISCSI_TMF_RSP_REJECTED
		}
		// return response to initiator
		return task.conn.buildRespPackage(OpSCSITaskResp, task, nil)
	}
	return nil, nil
}

func (s *ISCSITargetDriver) Stats() scsi.Stats {
	s.mu.RLock()
	stats := s.TargetStats
	stats.SCSIIOCount = map[int]int64{}
	for key, value := range s.TargetStats.SCSIIOCount {
		stats.SCSIIOCount[key] = value
	}
	s.mu.RUnlock()
	return stats
}

func (s *ISCSITargetDriver) UpdateStats(conn *iscsiConnection, resp *ISCSICommand) {
	s.mu.Lock()
	s.TargetStats.IsClientConnected = s.isClientConnected
	switch api.SCSICommandType(resp.SCSIOpCode) {
	case api.READ_6, api.READ_10, api.READ_12, api.READ_16:
		s.TargetStats.ReadIOPS += 1
		s.TargetStats.TotalReadTime += int64(time.Since(resp.StartTime))
		s.TargetStats.TotalReadBlockCount += int64(resp.ExpectedDataLen)
		break
	case api.WRITE_6, api.WRITE_10, api.WRITE_12, api.WRITE_16:
		s.TargetStats.WriteIOPS += 1
		s.TargetStats.TotalWriteTime += int64(time.Since(resp.StartTime))
		s.TargetStats.TotalWriteBlockCount += int64(resp.ExpectedDataLen)
		break
	}
	s.TargetStats.SCSIIOCount[(int)(resp.SCSIOpCode)] += 1
	s.mu.Unlock()
}
