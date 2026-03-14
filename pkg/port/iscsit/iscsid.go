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
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/config"
	"github.com/gostor/gotgt/pkg/scsi"
	"github.com/gostor/gotgt/pkg/util"
	log "github.com/sirupsen/logrus"
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

// tsihBitmap is a bitmap for efficient TSIH allocation/deallocation
// Uses circular counter for O(1) allocation
type tsihBitmap struct {
	mu     sync.Mutex
	bitmap []uint64 // Each uint64 stores the usage status of 64 TSIHs
	next   uint16   // Next candidate position for allocation
	used   uint16   // Number of used TSIHs
}

// newTSIHBitmap creates a new TSIH bitmap
// Reserves 0 and 65535 as special values
func newTSIHBitmap() *tsihBitmap {
	// Need 65536 bits = 1024 uint64s
	b := &tsihBitmap{
		bitmap: make([]uint64, 1024),
		next:   1, // Start from 1, 0 is reserved
	}
	// Mark 0 and 65535 as used (reserved values)
	b.bitmap[0] |= 1 << 0     // TSIH = 0
	b.bitmap[1023] |= 1 << 63 // TSIH = 65535
	b.used = 2
	return b
}

// alloc allocates an available TSIH using circular search strategy
func (b *tsihBitmap) alloc() uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.used >= ISCSI_MAX_TSIH-1 {
		return ISCSI_UNSPEC_TSIH
	}

	start := b.next
	for {
		idx := b.next / 64
		bit := b.next % 64

		if (b.bitmap[idx] & (1 << bit)) == 0 {
			// Found free slot
			b.bitmap[idx] |= 1 << bit
			b.used++
			result := b.next
			// Update next to next position
			b.next++
			if b.next >= ISCSI_MAX_TSIH {
				b.next = 1
			}
			return result
		}

		b.next++
		if b.next >= ISCSI_MAX_TSIH {
			b.next = 1
		}
		if b.next == start {
			// Looped around without finding
			return ISCSI_UNSPEC_TSIH
		}
	}
}

// release releases a TSIH
func (b *tsihBitmap) release(tsih uint16) {
	if tsih == 0 || tsih == ISCSI_MAX_TSIH {
		return // Cannot release reserved values
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	idx := tsih / 64
	bit := tsih % 64

	if (b.bitmap[idx] & (1 << bit)) != 0 {
		b.bitmap[idx] &^= 1 << bit
		b.used--
	}
}

var (
	EnableStats   bool
	CurrentHostIP string
	IPMutex       sync.Mutex
)

type ISCSITargetDriver struct {
	SCSI                   *scsi.SCSITargetService
	Name                   string
	iSCSITargets           map[string]*ISCSITarget
	tsihBitmap             *tsihBitmap
	isClientConnected      bool
	enableStats            bool
	mu                     *sync.RWMutex
	l                      net.Listener
	state                  uint8
	OpCode                 int
	TargetStats            scsi.Stats
	clusterIP              string
	blockMultipleHostLogin bool
}

func init() {
	scsi.RegisterTargetDriver(iSCSIDriverName, NewISCSITargetDriver)
}

func NewISCSITargetDriver(base *scsi.SCSITargetService) (scsi.SCSITargetDriver, error) {
	driver := &ISCSITargetDriver{
		Name:         iSCSIDriverName,
		iSCSITargets: map[string]*ISCSITarget{},
		SCSI:         base,
		tsihBitmap:   newTSIHBitmap(),
		mu:           &sync.RWMutex{},
	}

	if EnableStats {
		driver.enableStats = true
		driver.TargetStats.SCSIIOCount = map[int]int64{}
	}
	return driver, nil
}

func (s *ISCSITargetDriver) AllocTSIH() uint16 {
	return s.tsihBitmap.alloc()
}

func (s *ISCSITargetDriver) ReleaseTSIH(tsih uint16) {
	s.tsihBitmap.release(tsih)
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
		tgt.TPGTs[uint16(tpgtNumber)] = &iSCSITPGT{TPGT: uint16(tpgtNumber), Portals: make(map[string]struct{})}
		targetPortName := fmt.Sprintf("%s,t,0x%02x", tgtName, tpgtNumber)
		scsiTPG.TargetPortGroup = append(scsiTPG.TargetPortGroup, &api.SCSITargetPort{RelativeTargetPortID: uint16(tpgtNumber), TargetPortName: targetPortName})
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
		iscsiConn.rxIOState = IOSTATE_RX_BHS
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

func (s *ISCSITargetDriver) handler(events byte, conn *iscsiConnection) {

	if events&DATAIN != 0 {
		log.Debug("rx handler processing...")
		go func() {
			s.rxHandler(conn)
			if conn.state == CONN_STATE_CLOSE {
				log.Warningf("iscsi connection[%d] closed", conn.cid)
				conn.close()
				IPMutex.Lock()
				remoteIP := strings.Split(conn.conn.RemoteAddr().String(), ":")[0]
				if CurrentHostIP == remoteIP {
					CurrentHostIP = ""
				}
				IPMutex.Unlock()
			}
		}()
	}
	if conn.state != CONN_STATE_CLOSE && events&DATAOUT != 0 {
		log.Debug("tx handler processing...")
		s.txHandler(conn)
	}
	if conn.state == CONN_STATE_CLOSE {
		log.Warningf("iscsi connection[%d] closed", conn.cid)
		conn.close()
		IPMutex.Lock()
		remoteIP := strings.Split(conn.conn.RemoteAddr().String(), ":")[0]
		if CurrentHostIP == remoteIP {
			CurrentHostIP = ""
		}
		IPMutex.Unlock()
	}
}

func (s *ISCSITargetDriver) rxHandler(conn *iscsiConnection) {
	var (
		hdigest uint = 0
		ddigest uint = 0
		final   bool = false
		cmd     *ISCSICommand
		buf     []byte = getBuffer()
		length  int
		err     error
	)
	defer putBuffer(buf)

	conn.readLock.Lock()
	defer conn.readLock.Unlock()
	if conn.state == CONN_STATE_SCSI {
		hdigest = conn.loginParam.sessionParam[ISCSI_PARAM_HDRDGST_EN].Value & DIGEST_CRC32C
		ddigest = conn.loginParam.sessionParam[ISCSI_PARAM_DATADGST_EN].Value & DIGEST_CRC32C
	}
	for {
		switch conn.rxIOState {
		case IOSTATE_RX_BHS:
			log.Debug("rx handler: IOSTATE_RX_BHS")
			length, err = conn.readData(buf)
			if err != nil {
				log.Error("read BHS failed: ", err)
				conn.state = CONN_STATE_CLOSE
				return
			}
			if length == 0 {
				log.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
				return
			}
			cmd, err = parseHeader(buf)
			if err != nil {
				log.Error(err)
				log.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
				return
			}
			conn.req = cmd
			if length == BHS_SIZE && cmd.DataLen != 0 {
				conn.rxIOState = IOSTATE_RX_INIT_AHS
				break
			}
			if log.GetLevel() == log.DebugLevel {
				log.Debugf("got command: \n%s", cmd.String())
				log.Debugf("got buffer: %v", buf)
			}
			final = true
		case IOSTATE_RX_INIT_AHS:
			if hdigest != 0 {
				conn.rxIOState = IOSTATE_RX_INIT_HDIGEST
			} else {
				conn.rxIOState = IOSTATE_RX_DATA
			}
		case IOSTATE_RX_DATA:
			if ddigest != 0 {
				conn.rxIOState = IOSTATE_RX_INIT_DDIGEST
			}
			if cmd == nil {
				return
			}
			dl := ((cmd.DataLen + DataPadding - 1) / DataPadding) * DataPadding
			cmd.RawData = make([]byte, int(dl))
			length := 0
			for length < dl {
				l, err := conn.readData(cmd.RawData[length:])
				if err != nil {
					log.Error("read data failed:", err)
					conn.state = CONN_STATE_CLOSE
					return
				}
				length += l
			}
			if length != dl {
				log.Debugf("get length is %d, but expected %d", length, dl)
				log.Warning("set connection to close")
				conn.state = CONN_STATE_CLOSE
				return
			}
			final = true
		default:
			log.Errorf("error %d %d\n", conn.state, conn.rxIOState)
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
			log.Debug("OpLoginReq")
			if err := s.iscsiExecLogin(conn); err != nil {
				log.Error(err)
				log.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
			}
		case OpLogoutReq:
			log.Debug("OpLogoutReq")
			s.setClientStatus(false)
			if err := iscsiExecLogout(conn); err != nil {
				log.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
			}
		case OpTextReq:
			log.Debug("OpTextReq")
			if err := s.iscsiExecText(conn); err != nil {
				log.Warningf("set connection to close")
				conn.state = CONN_STATE_CLOSE
			}
		default:
			iscsiExecReject(conn)
		}
		log.Debugf("connection state is %v", conn.State())
		s.handler(DATAOUT, conn)
	}
}

func (s *ISCSITargetDriver) iscsiExecLogin(conn *iscsiConnection) error {
	var cmd = conn.req

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
			return err
		}
		conn.state = CONN_STATE_LOGIN
		return conn.buildRespPackage(OpLoginResp, nil)
	}

	if _, err := conn.processLoginData(); err != nil {
		return err
	}

	if !conn.loginParam.paramInit {
		if err := s.BindISCSISession(conn); err != nil {
			conn.state = CONN_STATE_EXIT
			return err
		}
		conn.loginParam.paramInit = true
	}
	if conn.loginParam.tgtNSG == FullFeaturePhase &&
		conn.loginParam.tgtTrans {
		conn.state = CONN_STATE_LOGIN_FULL
	} else {
		conn.state = CONN_STATE_LOGIN
	}

	return conn.buildRespPackage(OpLoginResp, nil)
}

func iscsiExecLogout(conn *iscsiConnection) error {
	log.Infof("Logout request received from initiator: %v", conn.conn.RemoteAddr().String())
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
		conn.resp.MaxCmdSN = conn.session.ExpCmdSN + conn.session.MaxQueueCommand
	}
	IPMutex.Lock()
	remoteIP := strings.Split(conn.conn.RemoteAddr().String(), ":")[0]
	if CurrentHostIP == remoteIP {
		CurrentHostIP = ""
	}
	IPMutex.Unlock()
	return nil
}

func (s *ISCSITargetDriver) iscsiExecText(conn *iscsiConnection) error {
	var result = []util.KeyValue{}
	cmd := conn.req
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
	return conn.buildRespPackage(OpNoopIn, nil)
}

// SNACK Type constants per RFC 7143
const (
	SNACK_TYPE_DATA_ACK   = 0 // Data ACK
	SNACK_TYPE_STATUS_ACK = 1 // Status ACK
	SNACK_TYPE_DATA_R2T   = 2 // Data R2T
	SNACK_TYPE_R_DATA     = 3 // R-Data
)

/*
 * iscsiExecSNACK handles SNACK (Sequence Number Acknowledgement) requests
 * SNACK is used for error recovery in iSCSI protocol per RFC 7143 section 11.9
 */
func (s *ISCSITargetDriver) iscsiExecSNACK(conn *iscsiConnection) error {
	req := conn.req
	// Parse SNACK type from byte 1, bits 0-1
	snackType := (req.SCSIOpCode >> 0) & 0x03
	// Parse BegRun and RunLength from the header
	begRun := req.ReferencedTaskTag
	runLength := req.R2TSN

	log.Debugf("SNACK request type=%d, BegRun=%d, RunLength=%d", snackType, begRun, runLength)

	switch snackType {
	case SNACK_TYPE_DATA_ACK:
		// Data ACK - initiator acknowledges receipt of Data-In PDUs
		// For ErrorRecoveryLevel >= 1, we could track acknowledged Data-In
		log.Debug("SNACK Data ACK received")
		// Simply return success for now
		conn.resp = &ISCSICommand{
			OpCode:   OpNoopIn,
			Final:    true,
			TaskTag:  req.TaskTag,
			StatSN:   conn.statSN,
			ExpCmdSN: conn.expCmdSN,
		}
		if conn.session != nil {
			conn.resp.MaxCmdSN = conn.session.ExpCmdSN + conn.session.MaxQueueCommand
		}
		return nil

	case SNACK_TYPE_STATUS_ACK:
		// Status ACK - initiator acknowledges receipt of status
		log.Debug("SNACK Status ACK received")
		// Similar to Data ACK, just acknowledge
		conn.resp = &ISCSICommand{
			OpCode:   OpNoopIn,
			Final:    true,
			TaskTag:  req.TaskTag,
			StatSN:   conn.statSN,
			ExpCmdSN: conn.expCmdSN,
		}
		if conn.session != nil {
			conn.resp.MaxCmdSN = conn.session.ExpCmdSN + conn.session.MaxQueueCommand
		}
		return nil

	case SNACK_TYPE_DATA_R2T:
		// Data R2T - request retransmission of R2T
		log.Debug("SNACK Data R2T received - requesting R2T retransmission")
		// Find the task and resend R2T
		conn.session.PendingTasksMutex.RLock()
		task := conn.session.PendingTasks.GetByTag(begRun)
		conn.session.PendingTasksMutex.RUnlock()
		if task == nil {
			log.Errorf("Cannot find task for R2T retransmission, tag=%d", begRun)
			return fmt.Errorf("task not found")
		}
		// Reset R2T state and resend
		task.r2tSN = runLength
		conn.rxTask = task
		return iscsiExecR2T(conn)

	case SNACK_TYPE_R_DATA:
		// R-Data - request retransmission of Data-In
		log.Debug("SNACK R-Data received - requesting Data-In retransmission")
		// For now, reject this as it requires complex data buffering
		// In a full implementation, we would need to buffer Data-In PDUs
		// and retransmit based on BegRun and RunLength
		log.Warn("R-Data SNACK not fully implemented")
		return fmt.Errorf("R-Data SNACK not supported")

	default:
		return fmt.Errorf("unknown SNACK type: %d", snackType)
	}
}

func iscsiExecReject(conn *iscsiConnection) error {
	return conn.buildRespPackage(OpReject, nil)
}

func iscsiExecR2T(conn *iscsiConnection) error {
	return conn.buildRespPackage(OpReady, nil)
}

func (s *ISCSITargetDriver) txHandler(conn *iscsiConnection) {
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
	if conn.state == CONN_STATE_SCSI && conn.txTask == nil {
		err := s.scsiCommandHandler(conn)
		if err != nil {
			log.Error(err)
			return
		}
	}
	resp := conn.resp
	segmentLen := conn.maxRecvDataSegmentLength
	transferLen := len(resp.RawData)
	resp.DataSN = 0
	maxCount := conn.maxSeqCount

	if s.enableStats {
		if resp.OpCode == OpSCSIResp || resp.OpCode == OpSCSIIn {
			s.UpdateStats(conn)
		}
	}

	/* send data splitted by segmentLen */
SendRemainingData:
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
		switch conn.txIOState {
		case IOSTATE_TX_BHS:
			if log.GetLevel() == log.DebugLevel {
				log.Debug("ready to write response")
				log.Debugf("response is %s", resp.String())
			}
			if l, err := conn.write(resp.Bytes()); err != nil {
				log.Errorf("failed to write data to client: %v", err)
				return
			} else {
				conn.txIOState = IOSTATE_TX_INIT_AHS
				log.Debugf("success to write %d length", l)
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
			log.Errorf("error %d %d\n", conn.state, conn.txIOState)
			return
		}

		if final {
			if resp.OpCode == OpSCSIIn && resp.Final != true {
				resp.DataSN++
				conn.txIOState = IOSTATE_TX_BHS
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
		conn.rxIOState = IOSTATE_RX_BHS
		s.handler(DATAIN, conn)
	case CONN_STATE_SECURITY_FULL, CONN_STATE_LOGIN_FULL:
		if conn.session.SessionType == SESSION_NORMAL {
			conn.state = CONN_STATE_KERNEL
			conn.state = CONN_STATE_SCSI
		} else {
			conn.state = CONN_STATE_FULL
		}
		conn.rxIOState = IOSTATE_RX_BHS
		s.handler(DATAIN, conn)
	case CONN_STATE_SCSI:
		conn.txTask = nil
	default:
		log.Warnf("unexpected connection state: %v", conn.State())
		conn.rxIOState = IOSTATE_RX_BHS
		s.handler(DATAIN, conn)
	}
}

func (s *ISCSITargetDriver) scsiCommandHandler(conn *iscsiConnection) (err error) {
	req := conn.req
	switch req.OpCode {
	case OpSCSICmd:
		log.Debugf("SCSI Command processing...")
		scmd := &api.SCSICommand{
			ITNexusID:       conn.session.ITNexus.ID,
			SCB:             req.CDB,
			SCBLength:       len(req.CDB),
			Lun:             req.LUN,
			Tag:             uint64(req.TaskTag),
			RelTargetPortID: conn.session.TPGT,
		}
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

		task := &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag, scmd: scmd}
		task.scmd.OpCode = conn.req.SCSIOpCode
		if scmd.Direction == api.SCSIDataBidirection {
			task.scmd.Result = api.SAMStatCheckCondition.Stat
			scsi.BuildSenseData(task.scmd, scsi.ILLEGAL_REQUEST, scsi.NO_ADDITIONAL_SENSE)
			conn.buildRespPackage(OpSCSIResp, task)
			conn.rxTask = nil
			break
		}
		if req.Write {
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
				scmd.OutSDBBuffer = &api.SCSIDataBuffer{
					Length: uint32(blen),
					Buffer: make([]byte, blen),
				}
			}
			log.Debugf("SCSI write, R2T count: %d, unsol Count: %d, offset: %d", task.r2tCount, task.unsolCount, task.offset)

			if conn.session.SessionParam[ISCSI_PARAM_IMM_DATA_EN].Value == 1 {
				copy(scmd.OutSDBBuffer.Buffer[task.offset:], conn.req.RawData)
				task.offset += conn.req.DataLen
			}
			if task.r2tCount > 0 {
				// prepare to receive more data
				conn.session.ExpCmdSN += 1
				task.state = taskPending
				conn.session.PendingTasksMutex.Lock()
				conn.session.PendingTasks.Push(task)
				conn.session.PendingTasksMutex.Unlock()
				conn.rxTask = task
				if conn.session.SessionParam[ISCSI_PARAM_INITIAL_R2T_EN].Value == 1 {
					iscsiExecR2T(conn)
					break
				} else {
					log.Debugf("Not ready to exec the task")
					conn.rxIOState = IOSTATE_RX_BHS
					s.handler(DATAIN, conn)
					return nil
				}
			}
		} else if scmd.InSDBBuffer == nil {
			scmd.InSDBBuffer = &api.SCSIDataBuffer{
				Length: uint32(req.ExpectedDataLen),
				Buffer: make([]byte, int(req.ExpectedDataLen)),
			}
		}
		task.offset = 0
		conn.rxTask = task
		if err = s.iscsiTaskQueueHandler(task); err != nil {
			if task.state == taskPending {
				s.handler(DATAIN, conn)
				err = nil
			}
			return
		} else {
			if scmd.Direction == api.SCSIDataRead && scmd.SenseBuffer == nil && req.ExpectedDataLen != 0 {
				conn.buildRespPackage(OpSCSIIn, task)
			} else {
				conn.buildRespPackage(OpSCSIResp, task)
			}
			conn.rxTask = nil
		}
	case OpSCSITaskReq:
		// task management function
		task := &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag, scmd: nil}
		conn.rxTask = task
		if err = s.iscsiTaskQueueHandler(task); err != nil {
			return
		}
	case OpSCSIOut:
		log.Debugf("iSCSI Data-out processing...")
		conn.session.PendingTasksMutex.RLock()
		task := conn.session.PendingTasks.GetByTag(conn.req.TaskTag)
		conn.session.PendingTasksMutex.RUnlock()
		if task == nil {
			err = fmt.Errorf("Cannot find iSCSI task with tag[%v]", conn.req.TaskTag)
			log.Error(err)
			return
		}
		copy(task.scmd.OutSDBBuffer.Buffer[task.offset:], conn.req.RawData)
		task.offset += conn.req.DataLen
		task.r2tCount = task.r2tCount - conn.req.DataLen
		log.Debugf("Final: %v", conn.req.Final)
		log.Debugf("r2tCount: %v", task.r2tCount)
		if !conn.req.Final {
			log.Debugf("Not ready to exec the task")
			conn.rxIOState = IOSTATE_RX_BHS
			s.handler(DATAIN, conn)
			return nil
		} else if task.r2tCount > 0 {
			// prepare to receive more data
			if task.unsolCount == 0 {
				task.r2tSN += 1
			} else {
				task.r2tSN = 0
				task.unsolCount = 0
			}
			conn.rxTask = task
			iscsiExecR2T(conn)
			break
		}
		task.offset = 0
		log.Debugf("Process the Data-out package")
		conn.rxTask = task
		if err = s.iscsiExecTask(task); err != nil {
			return
		} else {
			conn.buildRespPackage(OpSCSIResp, task)
			conn.rxTask = nil
			conn.session.PendingTasksMutex.Lock()
			conn.session.PendingTasks.RemoveByTag(conn.req.TaskTag)
			conn.session.PendingTasksMutex.Unlock()
		}
	case OpNoopOut:
		iscsiExecNoopOut(conn)
	case OpLogoutReq:
		s.setClientStatus(false)
		conn.txTask = &iscsiTask{conn: conn, cmd: conn.req, tag: conn.req.TaskTag}
		conn.txIOState = IOSTATE_TX_BHS
		iscsiExecLogout(conn)
	case OpTextReq:
		err = fmt.Errorf("Cannot handle yet %s", opCodeMap[conn.req.OpCode])
		log.Error(err)
		return
	case OpSNACKReq:
		log.Debug("SNACK Request processing...")
		if err := s.iscsiExecSNACK(conn); err != nil {
			log.Errorf("SNACK handling failed: %v", err)
			iscsiExecReject(conn)
		}
	default:
		err = fmt.Errorf("Unknown op %s", opCodeMap[conn.req.OpCode])
		log.Error(err)
		return
	}
	conn.rxIOState = IOSTATE_RX_BHS
	s.handler(DATAIN|DATAOUT, conn)
	return nil
}

func (s *ISCSITargetDriver) iscsiTaskQueueHandler(task *iscsiTask) error {
	conn := task.conn
	sess := conn.session
	cmd := task.cmd
	if cmd.Immediate {
		return s.iscsiExecTask(task)
	}
	cmdsn := cmd.CmdSN
	log.Debugf("CmdSN of command is %d", cmdsn)
	if cmdsn == sess.ExpCmdSN {
	retry:
		cmdsn += 1
		sess.ExpCmdSN = cmdsn
		log.Debugf("session's ExpCmdSN is %d", cmdsn)

		log.Debugf("process task(%d)", task.cmd.CmdSN)
		if err := s.iscsiExecTask(task); err != nil {
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
			sess.PendingTasks.Push(task)
			sess.PendingTasksMutex.Unlock()
			return nil
		}
		task.state = taskSCSI
		sess.PendingTasksMutex.Unlock()
		goto retry
	}
	// cmd.CmdSN != sess.ExpCmdSN
	if cmd.CmdSN < sess.ExpCmdSN {
		err := fmt.Errorf("unexpected cmd serial number: (%d, %d)", cmd.CmdSN, sess.ExpCmdSN)
		log.Error(err)
		return err
	}
	log.Debugf("add task(%d) into task queue", task.cmd.CmdSN)
	// add this task into queue and set it as a pending task
	sess.PendingTasksMutex.Lock()
	task.state = taskPending
	sess.PendingTasks.Push(task)
	sess.PendingTasksMutex.Unlock()
	return fmt.Errorf("pending")
}

func (s *ISCSITargetDriver) iscsiExecTask(task *iscsiTask) error {
	cmd := task.cmd
	switch cmd.OpCode {
	case OpSCSICmd, OpSCSIOut:
		task.state = taskSCSI
		// add scsi target process queue
		err := s.SCSI.AddCommandQueue(task.conn.session.Target.SCSITarget.TID, task.scmd)
		if err != nil {
			task.state = 0
		}
		return err
	case OpLogoutReq:

	case OpNoopOut:
		// just do it in iscsi layer
	case OpSCSITaskReq:
		sess := task.conn.session
		switch cmd.TaskFunc {
		case ISCSI_TM_FUNC_ABORT_TASK:
			sess.PendingTasksMutex.Lock()
			stask := sess.PendingTasks.RemoveByTag(cmd.ReferencedTaskTag)
			sess.PendingTasksMutex.Unlock()
			if stask == nil {
				task.result = ISCSI_TMF_RSP_NO_TASK
			} else {
				// abort this task
				log.Debugf("abort the task[%v]", stask.tag)
				if stask.scmd == nil {
					stask.scmd = &api.SCSICommand{Result: api.SAM_STAT_TASK_ABORTED}
				}
				stask.conn = task.conn
				log.Debugf("stask.conn: %#v", stask.conn)
				stask.conn.buildRespPackage(OpSCSIResp, stask)
				stask.conn.rxTask = nil
				s.handler(DATAOUT, stask.conn)
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
		return task.conn.buildRespPackage(OpSCSITaskResp, task)
	}
	return nil
}

// Async Event types per RFC 7143
const (
	ASYNC_EVENT_SCSI      = 0   // SCSI Asynchronous Event
	ASYNC_EVENT_STATUS    = 1   // iSCSI Status Update
	ASYNC_EVENT_LOGOUT    = 2   // iSCSI Logout Request
	ASYNC_EVENT_DROP_CONN = 3   // iSCSI Drop Connection
	ASYNC_EVENT_DROP_SESS = 4   // iSCSI Drop All Connections
	ASYNC_EVENT_NOP       = 5   // iSCSI NOP
	ASYNC_EVENT_VENDOR    = 255 // Vendor Specific Event
)

/*
 * SendAsyncMessage sends an asynchronous message to the initiator
 * This implements RFC 7143 section 11.10 Asynchronous Message
 */
func (s *ISCSITargetDriver) SendAsyncMessage(conn *iscsiConnection, eventType byte, lun [8]uint8, param1, param2 uint32, data []byte) error {
	if conn == nil || conn.state != CONN_STATE_SCSI {
		return fmt.Errorf("connection not ready for async message")
	}

	conn.statSN += 1
	conn.resp = &ISCSICommand{
		OpCode:     OpAsync,
		SCSIOpCode: eventType,
		Final:      true,
		LUN:        lun,
		StatSN:     conn.statSN,
		ExpCmdSN:   conn.expCmdSN,
		RawData:    data,
	}
	if conn.session != nil {
		conn.resp.MaxCmdSN = conn.session.ExpCmdSN + conn.session.MaxQueueCommand
	}

	// Parameter1 and Parameter2 are encoded in RawData or could be stored in ISCSICommand
	// For simplicity, we encode them at the start of RawData if not already present
	if len(data) == 0 && (param1 != 0 || param2 != 0) {
		conn.resp.RawData = make([]byte, 8)
		copy(conn.resp.RawData[0:4], util.MarshalUint32(param1))
		copy(conn.resp.RawData[4:8], util.MarshalUint32(param2))
	}

	log.Debugf("Sending Async message type=%d to initiator", eventType)
	s.handler(DATAOUT, conn)
	return nil
}

// SendSCSIAsyncEvent sends a SCSI asynchronous event (e.g., LUN reset, storage change)
func (s *ISCSITargetDriver) SendSCSIAsyncEvent(conn *iscsiConnection, lun [8]uint8, eventCode byte) error {
	// SCSI Async Event data format:
	// bytes 0-1: Event Code
	// bytes 2-3: Reserved
	// bytes 4+: Event-specific data
	data := []byte{eventCode, 0, 0, 0}
	return s.SendAsyncMessage(conn, ASYNC_EVENT_SCSI, lun, 0, 0, data)
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

func (s *ISCSITargetDriver) UpdateStats(conn *iscsiConnection) {
	s.mu.Lock()
	s.TargetStats.IsClientConnected = s.isClientConnected
	switch api.SCSICommandType(conn.resp.SCSIOpCode) {
	case api.READ_6, api.READ_10, api.READ_12, api.READ_16:
		s.TargetStats.ReadIOPS += 1
		s.TargetStats.TotalReadTime += int64(time.Since(conn.resp.StartTime))
		s.TargetStats.TotalReadBlockCount += int64(conn.resp.ExpectedDataLen)
		break
	case api.WRITE_6, api.WRITE_10, api.WRITE_12, api.WRITE_16:
		s.TargetStats.WriteIOPS += 1
		s.TargetStats.TotalWriteTime += int64(time.Since(conn.resp.StartTime))
		s.TargetStats.TotalWriteBlockCount += int64(conn.resp.ExpectedDataLen)
		break
	}
	s.TargetStats.SCSIIOCount[(int)(conn.resp.SCSIOpCode)] += 1
	s.mu.Unlock()
}
