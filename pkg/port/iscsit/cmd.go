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
	"strings"
	"sync"
	"time"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/util"
	"github.com/gostor/gotgt/pkg/util/numa"
	log "github.com/sirupsen/logrus"
)

// Object pools to reduce GC pressure
var (
	// commandPool reuses ISCSICommand objects
	commandPool = sync.Pool{
		New: func() interface{} {
			return &ISCSICommand{}
		},
	}

	// bufferPool reuses small buffers for BHS reading
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, BHS_SIZE)
			return &buf
		},
	}

	// numaBufferPool NUMA-aware buffer pool for larger I/O operations
	numaBufferPool *numa.NUMABufferPool
	numaPoolOnce   sync.Once
)

// initNUMAPool initializes the NUMA-aware buffer pool
func initNUMAPool() {
	numaPoolOnce.Do(func() {
		numaBufferPool = numa.NewNUMABufferPool(&numa.BufferPoolConfig{
			BufferSize:      256 * 1024, // 256KB for I/O buffers
			PerNodePoolSize: 512,
			EnableNUMA:      numa.Available(),
		})
	})
}

// getCommand gets an ISCSICommand from the pool
func getCommand() *ISCSICommand {
	return commandPool.Get().(*ISCSICommand)
}

// putCommand puts an ISCSICommand back to the pool
func putCommand(cmd *ISCSICommand) {
	if cmd == nil {
		return
	}
	// Clear sensitive data
	cmd.RawData = nil
	cmd.RawHeader = nil
	cmd.CDB = nil
	cmd.DataLen = 0
	*cmd = ISCSICommand{}
	commandPool.Put(cmd)
}

// getBuffer gets a buffer from the pool
func getBuffer() []byte {
	return *bufferPool.Get().(*[]byte)
}

// putBuffer puts a buffer back to the pool
func putBuffer(buf []byte) {
	if cap(buf) >= BHS_SIZE {
		bufferPool.Put(&buf)
	}
}

// getIOBuffer gets a NUMA-aware I/O buffer for larger data operations
func getIOBuffer(size int) []byte {
	initNUMAPool()
	if size <= numaBufferPool.GetConfig().BufferSize {
		return numaBufferPool.Get()[:size]
	}
	return make([]byte, size)
}

// putIOBuffer puts a NUMA-aware I/O buffer back to the pool
func putIOBuffer(buf []byte) {
	if numaBufferPool != nil && cap(buf) >= numaBufferPool.GetConfig().BufferSize {
		numaBufferPool.Put(buf)
	}
}

// NUMAStats returns NUMA buffer pool statistics
func NUMAStats() numa.PoolStats {
	if numaBufferPool == nil {
		return numa.PoolStats{}
	}
	return numaBufferPool.Stats()
}

type OpCode int

const (
	// Defined on the initiator.
	OpNoopOut     OpCode = 0x00
	OpSCSICmd            = 0x01
	OpSCSITaskReq        = 0x02
	OpLoginReq           = 0x03
	OpTextReq            = 0x04
	OpSCSIOut            = 0x05
	OpLogoutReq          = 0x06
	OpSNACKReq           = 0x10
	// Defined on the target.
	OpNoopIn       OpCode = 0x20
	OpSCSIResp            = 0x21
	OpSCSITaskResp        = 0x22
	OpLoginResp           = 0x23
	OpTextResp            = 0x24
	OpSCSIIn              = 0x25
	OpLogoutResp          = 0x26
	OpReady               = 0x31
	OpAsync               = 0x32
	OpReject              = 0x3f
)

const (
	MaxBurstLength           uint32 = 262144
	MaxRecvDataSegmentLength uint32 = 65536
)

var opCodeMap = map[OpCode]string{
	OpNoopOut:      "NOP-Out",
	OpSCSICmd:      "SCSI Command",
	OpSCSITaskReq:  "SCSI Task Management FunctionRequest",
	OpLoginReq:     "Login Request",
	OpTextReq:      "Text Request",
	OpSCSIOut:      "SCSI Data-Out (write)",
	OpLogoutReq:    "Logout Request",
	OpSNACKReq:     "SNACK Request",
	OpNoopIn:       "NOP-In",
	OpSCSIResp:     "SCSI Response",
	OpSCSITaskResp: "SCSI Task Management Function Response",
	OpLoginResp:    "Login Response",
	OpTextResp:     "Text Response",
	OpSCSIIn:       "SCSI Data-In (read)",
	OpLogoutResp:   "Logout Response",
	OpReady:        "Ready To Transfer (R2T)",
	OpAsync:        "Asynchronous Message",
	OpReject:       "Reject",
}

const DataPadding = 4

type ISCSITaskManagementFunc struct {
	Result            byte
	TaskFunc          uint32
	ReferencedTaskTag uint32
}

type ISCSICommand struct {
	OpCode             OpCode
	RawHeader          []byte
	DataLen            int
	RawData            []byte
	Final              bool
	FinalInSeq         bool
	Immediate          bool
	TaskTag            uint32
	StartTime          time.Time
	ExpCmdSN, MaxCmdSN uint32
	AHSLen             int
	Resid              uint32

	// Connection ID.
	ConnID uint16
	// Command serial number.
	CmdSN uint32
	// Expected status serial.
	ExpStatSN uint32

	Read, Write bool
	LUN         [8]uint8
	// Transit bit.
	Transit bool
	// Continue bit.
	Cont bool
	// Current Stage, Next Stage.
	CSG, NSG iSCSILoginStage
	// Initiator part of the SSID.
	ISID uint64
	// Target-assigned Session Identifying Handle.
	TSIH uint16
	// Status serial number.
	StatSN uint32

	// For login response.
	StatusClass  uint8
	StatusDetail uint8

	// SCSI commands
	SCSIOpCode      byte
	ExpectedDataLen uint32
	CDB             []byte
	Status          byte
	SCSIResponse    byte

	// Task request
	ISCSITaskManagementFunc

	// R2T
	R2TSN         uint32
	DesiredLength uint32

	// Data-In/Out
	HasStatus    bool
	DataSN       uint32
	BufferOffset uint32
}

func (cmd *ISCSICommand) Bytes() []byte {
	switch cmd.OpCode {
	case OpLoginResp:
		return cmd.loginRespBytes()
	case OpLogoutResp:
		return cmd.logoutRespBytes()
	case OpSCSIResp:
		return cmd.scsiCmdRespBytes()
	case OpSCSIIn:
		return cmd.dataInBytes()
	case OpTextResp:
		return cmd.textRespBytes()
	case OpNoopIn:
		return cmd.noopInBytes()
	case OpSCSITaskResp:
		return cmd.scsiTMFRespBytes()
	case OpReady:
		return cmd.r2tRespBytes()
	case OpAsync:
		return cmd.asyncMsgBytes()
	}
	return nil
}

func (m *ISCSICommand) String() string {
	var s []string
	s = append(s, fmt.Sprintf("Op: %v", opCodeMap[m.OpCode]))
	s = append(s, fmt.Sprintf("Final = %v", m.Final))
	s = append(s, fmt.Sprintf("Immediate = %v", m.Immediate))
	s = append(s, fmt.Sprintf("Data Segment Length = %d", m.DataLen))
	s = append(s, fmt.Sprintf("Task Tag = %x", m.TaskTag))
	s = append(s, fmt.Sprintf("AHS Length = %d", m.AHSLen))
	switch m.OpCode {
	case OpLoginReq:
		s = append(s, fmt.Sprintf("ISID = %x", m.ISID))
		s = append(s, fmt.Sprintf("Transit = %v", m.Transit))
		s = append(s, fmt.Sprintf("Continue = %v", m.Cont))
		s = append(s, fmt.Sprintf("Current Stage = %v", m.CSG))
		s = append(s, fmt.Sprintf("Next Stage = %v", m.NSG))
	case OpLoginResp:
		s = append(s, fmt.Sprintf("ISID = %x", m.ISID))
		s = append(s, fmt.Sprintf("Transit = %v", m.Transit))
		s = append(s, fmt.Sprintf("Continue = %v", m.Cont))
		s = append(s, fmt.Sprintf("Current Stage = %v", m.CSG))
		s = append(s, fmt.Sprintf("Next Stage = %v", m.NSG))
		s = append(s, fmt.Sprintf("Status Class = %d", m.StatusClass))
		s = append(s, fmt.Sprintf("Status Detail = %d", m.StatusDetail))
	case OpSCSICmd, OpSCSIOut, OpSCSIIn:
		s = append(s, fmt.Sprintf("LUN = %d", m.LUN))
		s = append(s, fmt.Sprintf("ExpectedDataLen = %d", m.ExpectedDataLen))
		s = append(s, fmt.Sprintf("CmdSN = %d", m.CmdSN))
		s = append(s, fmt.Sprintf("ExpStatSN = %d", m.ExpStatSN))
		s = append(s, fmt.Sprintf("Read = %v", m.Read))
		s = append(s, fmt.Sprintf("Write = %v", m.Write))
		s = append(s, fmt.Sprintf("CDB = %x", m.CDB))
	case OpSCSIResp:
		s = append(s, fmt.Sprintf("StatSN = %d", m.StatSN))
		s = append(s, fmt.Sprintf("ExpCmdSN = %d", m.ExpCmdSN))
		s = append(s, fmt.Sprintf("MaxCmdSN = %d", m.MaxCmdSN))
	}
	return strings.Join(s, "\n")
}

// parseUint parses the given slice as a network-byte-ordered integer.  If
// there are more than 8 bytes in data, it overflows.
func ParseUint(data []byte) uint64 {
	var out uint64
	for i := 0; i < len(data); i++ {
		out += uint64(data[len(data)-i-1]) << uint(8*i)
	}
	return out
}

func parseHeader(data []byte) (*ISCSICommand, error) {
	if len(data) != BHS_SIZE {
		return nil, fmt.Errorf("garbled header")
	}
	// TODO: sync.Pool
	m := &ISCSICommand{}
	m.Immediate = 0x40&data[0] == 0x40
	m.OpCode = OpCode(data[0] & ISCSI_OPCODE_MASK)
	m.Final = 0x80&data[1] == 0x80
	m.AHSLen = int(data[4]) * 4
	m.DataLen = int(ParseUint(data[5:8]))
	m.TaskTag = uint32(ParseUint(data[16:20]))
	m.StartTime = time.Now()
	switch m.OpCode {
	case OpSCSICmd:
		m.LUN = [8]byte{data[9]}
		m.ExpectedDataLen = uint32(ParseUint(data[20:24]))
		m.CmdSN = uint32(ParseUint(data[24:28]))
		m.Read = data[1]&0x40 == 0x40
		m.Write = data[1]&0x20 == 0x20
		m.CDB = append([]byte{}, data[32:48]...)
		m.ExpStatSN = uint32(ParseUint(data[28:32]))
		m.SCSIOpCode = m.CDB[0]
		SCSIOpcode := api.SCSICommandType(m.SCSIOpCode)
		switch SCSIOpcode {
		case api.READ_6, api.READ_10, api.READ_12, api.READ_16:
			m.Read = true
		case api.WRITE_6, api.WRITE_10, api.WRITE_12, api.WRITE_16, api.WRITE_VERIFY, api.WRITE_VERIFY_12, api.WRITE_VERIFY_16:
			m.Write = true
		}
		fallthrough
	case OpSCSITaskReq:
		m.ReferencedTaskTag = uint32(ParseUint(data[20:24]))
		m.TaskFunc = uint32(data[1] & ISCSI_FLAG_TM_FUNC_MASK)
	case OpSCSIResp:
	case OpSCSIOut:
		m.LUN = [8]byte{data[9]}
		m.ExpStatSN = uint32(ParseUint(data[28:32]))
		m.DataSN = uint32(ParseUint(data[36:40]))
		m.BufferOffset = uint32(ParseUint(data[40:44]))
	case OpLoginReq, OpTextReq, OpNoopOut, OpLogoutReq:
		m.Transit = m.Final
		m.Cont = data[1]&0x40 == 0x40
		if m.Cont && m.Transit {
			// rfc7143 11.12.2
			return nil, fmt.Errorf("transit and continue bits set in same login request")
		}
		m.CSG = iSCSILoginStage(data[1]&0xc) >> 2
		m.NSG = iSCSILoginStage(data[1] & 0x3)
		m.ISID = uint64(ParseUint(data[8:14]))
		m.TSIH = uint16(ParseUint(data[14:16]))
		m.ConnID = uint16(ParseUint(data[20:22]))
		m.CmdSN = uint32(ParseUint(data[24:28]))
		m.ExpStatSN = uint32(ParseUint(data[28:32]))
	case OpLoginResp:
		m.Transit = m.Final
		m.Cont = data[1]&0x40 == 0x40
		if m.Cont && m.Transit {
			// rfc7143 11.12.2
			return nil, fmt.Errorf("transit and continue bits set in same login request")
		}
		m.CSG = iSCSILoginStage(data[1]&0xc) >> 2
		m.NSG = iSCSILoginStage(data[1] & 0x3)
		m.StatSN = uint32(ParseUint(data[24:28]))
		m.ExpCmdSN = uint32(ParseUint(data[28:32]))
		m.MaxCmdSN = uint32(ParseUint(data[32:36]))
		m.StatusClass = uint8(data[36])
		m.StatusDetail = uint8(data[37])
	}
	return m, nil
}

func (m *ISCSICommand) scsiCmdRespBytes() []byte {
	// rfc7143 11.4 - BHS 48 bytes + data (4-byte aligned)
	rawDataLen := len(m.RawData)
	padding := (4 - rawDataLen%4) % 4
	buf := make([]byte, 48+rawDataLen+padding)

	buf[0] = byte(OpSCSIResp)
	var flag byte = 0x80
	if m.Resid > 0 {
		if m.Resid > m.ExpectedDataLen {
			flag |= 0x04
		} else {
			flag |= 0x02
		}
	}
	buf[1] = flag
	buf[2] = byte(m.SCSIResponse)
	buf[3] = byte(m.Status)

	// byte 4 is reserved (0)
	// Write data length (24-bit big-endian) at bytes 5-7
	buf[5] = byte(rawDataLen >> 16)
	buf[6] = byte(rawDataLen >> 8)
	buf[7] = byte(rawDataLen)
	// bytes 9-15 are reserved (0)
	// TaskTag at bytes 16-19 (32-bit big-endian)
	util.MarshalUint32To(buf[16:], m.TaskTag)
	// bytes 20-23 are reserved (0)
	// StatSN at bytes 24-27
	util.MarshalUint32To(buf[24:], m.StatSN)
	// ExpCmdSN at bytes 28-31
	util.MarshalUint32To(buf[28:], m.ExpCmdSN)
	// MaxCmdSN at bytes 32-35
	util.MarshalUint32To(buf[32:], m.MaxCmdSN)
	// bytes 36-43 are reserved (0)
	// Resid at bytes 44-47
	util.MarshalUint32To(buf[44:], m.Resid)
	copy(buf[48:], m.RawData)
	// padding bytes are already zero

	return buf
}

func (m *ISCSICommand) dataInBytes() []byte {
	// rfc7143 11.7
	// Calculate padded length using bit operation instead of loop
	dl := (m.DataLen + 3) &^ 3 // Round up to multiple of 4
	buf := make([]byte, 48+dl)

	buf[0] = byte(OpSCSIIn)
	var flag byte
	if m.FinalInSeq || m.Final {
		flag |= 0x80
	}
	if m.HasStatus && m.Final {
		flag |= 0x01
	}
	log.Debugf("resid: %v, ExpectedDataLen: %v", m.Resid, m.ExpectedDataLen)
	if m.Resid > 0 {
		if m.Resid > m.ExpectedDataLen {
			flag |= 0x04
		} else if m.Resid < m.ExpectedDataLen {
			flag |= 0x02
		}
	}
	buf[1] = flag
	if m.HasStatus && m.Final {
		buf[3] = byte(m.Status)
	}
	// Data length (24-bit) at bytes 5-7
	buf[5] = byte(m.DataLen >> 16)
	buf[6] = byte(m.DataLen >> 8)
	buf[7] = byte(m.DataLen)
	// Skip through to byte 16 Since A bit is not set 11.7.4
	util.MarshalUint32To(buf[16:], m.TaskTag)
	util.MarshalUint32To(buf[24:], m.StatSN)
	util.MarshalUint32To(buf[28:], m.ExpCmdSN)
	util.MarshalUint32To(buf[32:], m.MaxCmdSN)
	util.MarshalUint32To(buf[36:], m.DataSN)
	util.MarshalUint32To(buf[40:], m.BufferOffset)
	util.MarshalUint32To(buf[44:], m.Resid)
	if m.DataLen != 0 {
		copy(buf[48:], m.RawData[m.BufferOffset:m.BufferOffset+uint32(m.DataLen)])
	}

	return buf
}

func (m *ISCSICommand) textRespBytes() []byte {
	// Pre-calculate required capacity: BHS(48 bytes) + data (4-byte aligned)
	dataLen := len(m.RawData)
	padding := (4 - dataLen%4) % 4

	buf := make([]byte, 48+dataLen+padding)

	buf[0] = byte(OpTextResp)
	var b byte
	if m.Final {
		b |= 0x80
	}
	if m.Cont {
		b |= 0x40
	}
	// byte 1
	buf[1] = b

	// bytes 2,3,4 reserved (0)
	// bytes 5-8: data segment length (24-bit)
	buf[5] = byte(dataLen >> 16)
	buf[6] = byte(dataLen >> 8)
	buf[7] = byte(dataLen)
	// bytes 8-15 are reserved (0)
	// bytes 16-19: TaskTag
	util.MarshalUint32To(buf[16:], m.TaskTag)
	// bytes 20-23: 0xffffffff
	buf[20] = 0xff
	buf[21] = 0xff
	buf[22] = 0xff
	buf[23] = 0xff
	// bytes 24-27: StatSN
	util.MarshalUint32To(buf[24:], m.StatSN)
	// bytes 28-31: ExpCmdSN
	util.MarshalUint32To(buf[28:], m.ExpCmdSN)
	// bytes 32-35: MaxCmdSN
	util.MarshalUint32To(buf[32:], m.MaxCmdSN)
	// bytes 36-47 are reserved (0)
	// Copy data
	copy(buf[48:], m.RawData)
	// padding bytes are already zero
	return buf
}

func (m *ISCSICommand) noopInBytes() []byte {
	// rfc7143 11.11 - BHS 48 bytes + data (4-byte aligned)
	rawDataLen := len(m.RawData)
	padding := (4 - rawDataLen%4) % 4
	buf := make([]byte, 48+rawDataLen+padding)

	buf[0] = byte(OpNoopIn)
	buf[1] = 0x80
	// bytes 2-3 are reserved (0)
	// bytes 4-7: data segment length (32-bit)
	util.MarshalUint32To(buf[4:], uint32(rawDataLen))
	// bytes 8-15 are reserved (0)
	// bytes 16-19: TaskTag
	util.MarshalUint32To(buf[16:], m.TaskTag)
	// bytes 20-23: 0xffffffff
	buf[20] = 0xff
	buf[21] = 0xff
	buf[22] = 0xff
	buf[23] = 0xff
	// bytes 24-27: StatSN
	util.MarshalUint32To(buf[24:], m.StatSN)
	// bytes 28-31: ExpCmdSN
	util.MarshalUint32To(buf[28:], m.ExpCmdSN)
	// bytes 32-35: MaxCmdSN
	util.MarshalUint32To(buf[32:], m.MaxCmdSN)
	// bytes 36-47 are reserved (0)
	copy(buf[48:], m.RawData)
	// padding bytes are already zero
	return buf
}

func (m *ISCSICommand) scsiTMFRespBytes() []byte {
	// rfc7143 11.6 - Fixed 48 bytes
	buf := make([]byte, 48)
	buf[0] = byte(OpSCSITaskResp)
	buf[1] = 0x80
	buf[2] = m.Result
	// byte 3 is reserved (0)
	// bytes 4-15 are reserved (0)
	// bytes 16-19: TaskTag
	util.MarshalUint32To(buf[16:], m.TaskTag)
	// bytes 20-23 are reserved (0)
	// bytes 24-27: StatSN
	util.MarshalUint32To(buf[24:], m.StatSN)
	// bytes 28-31: ExpCmdSN
	util.MarshalUint32To(buf[28:], m.ExpCmdSN)
	// bytes 32-35: MaxCmdSN
	util.MarshalUint32To(buf[32:], m.MaxCmdSN)
	// bytes 36-47 are reserved (0)
	return buf
}

func (m *ISCSICommand) r2tRespBytes() []byte {
	// rfc7143 11.8 - Fixed 48 bytes
	buf := make([]byte, 48)
	buf[0] = byte(OpReady)
	if m.Final {
		buf[1] = 0x80
	}
	// bytes 2-15 are reserved (0)
	// bytes 16-19: TaskTag
	util.MarshalUint32To(buf[16:], m.TaskTag)
	// bytes 20-23 are reserved (0)
	// bytes 24-27: StatSN
	util.MarshalUint32To(buf[24:], m.StatSN)
	// bytes 28-31: ExpCmdSN
	util.MarshalUint32To(buf[28:], m.ExpCmdSN)
	// bytes 32-35: MaxCmdSN
	util.MarshalUint32To(buf[32:], m.MaxCmdSN)
	// bytes 36-39: R2TSN
	util.MarshalUint32To(buf[36:], m.R2TSN)
	// bytes 40-43: BufferOffset
	util.MarshalUint32To(buf[40:], m.BufferOffset)
	// bytes 44-47: DesiredLength
	util.MarshalUint32To(buf[44:], m.DesiredLength)
	return buf
}

// asyncMsgBytes implements RFC 7143 section 11.10 - Asynchronous Message
func (m *ISCSICommand) asyncMsgBytes() []byte {
	// rfc7143 11.10 - BHS 48 bytes + data (4-byte aligned)
	rawDataLen := len(m.RawData)
	padding := (4 - rawDataLen%4) % 4
	buf := make([]byte, 48+rawDataLen+padding)

	buf[0] = byte(OpAsync)
	// byte 1: AsyncEvent in bits 0-4
	buf[1] = byte(m.SCSIOpCode & 0x1f)
	// bytes 2-3 are reserved (0)

	// byte 4: 0x80 if AsyncEvent is 0 (SCSI Asynchronous Event)
	if m.SCSIOpCode == 0 {
		buf[4] = 0x80
	}

	// bytes 5-7: data segment length (24-bit)
	buf[5] = byte(rawDataLen >> 16)
	buf[6] = byte(rawDataLen >> 8)
	buf[7] = byte(rawDataLen)
	// bytes 8-15: LUN (if applicable)
	copy(buf[8:], m.LUN[:])
	// bytes 16-19: Reserved (0)
	// bytes 20-23: Target Transfer Tag (0xffffffff for Async)
	buf[20] = 0xff
	buf[21] = 0xff
	buf[22] = 0xff
	buf[23] = 0xff
	// bytes 24-27: StatSN
	util.MarshalUint32To(buf[24:], m.StatSN)
	// bytes 28-31: ExpCmdSN
	util.MarshalUint32To(buf[28:], m.ExpCmdSN)
	// bytes 32-35: MaxCmdSN
	util.MarshalUint32To(buf[32:], m.MaxCmdSN)
	// bytes 36-43: Reserved (0)
	// bytes 44-47: Parameter1 and Parameter2 (context-specific)
	copy(buf[48:], m.RawData)
	return buf
}
