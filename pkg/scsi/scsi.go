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
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/golang/glog"
	"github.com/gostor/gotgt/pkg/api"
)

type SCSITargetService struct {
	mutex   sync.RWMutex
	Targets []*api.SCSITarget
}

var _instance *SCSITargetService

func NewSCSITargetService() *SCSITargetService {
	if _instance == nil {
		_instance = &SCSITargetService{Targets: []*api.SCSITarget{}}
	}
	return _instance
}

func (s *SCSITargetService) GetTargetList() ([]api.SCSITarget, error) {
	result := []api.SCSITarget{}
	s.mutex.RLock()
	for _, t := range s.Targets {
		result = append(result, *t)
	}
	s.mutex.RUnlock()
	return result, nil
}

func (s *SCSITargetService) AddCommandQueue(tid int, scmd *api.SCSICommand) error {
	var (
		target *api.SCSITarget
		itn    *api.ITNexus
	)
	s.mutex.RLock()
	for _, t := range s.Targets {
		if t.TID == tid {
			target = t
			break
		}
	}
	s.mutex.RUnlock()
	if target == nil {
		return fmt.Errorf("Cannot find the target with ID(%d)", tid)
	}
	scmd.Target = target
	for _, it := range target.ITNexus {
		if it.ID == scmd.CommandITNID {
			itn = it
			break
		}
	}
	scmd.ITNexus = itn

	scmd.Device = target.Devices[0]
	result := scmd.Device.PerformCommand(tid, scmd)
	scmd.Result = result.Stat
	if result.Err != nil {
		glog.Error(result.Err)
		return result.Err
	}
	return nil
}

type SCSIServiceAction struct {
	ServiceAction      uint32
	CommandPerformFunc api.CommandFunc
}

type SCSIDeviceOperation struct {
	CommandPerformFunc api.CommandFunc
	ServiceAction      *SCSIServiceAction
	PRConflictBits     uint8
}

type BaseSCSIDeviceProtocol struct {
	Type          api.SCSIDeviceType
	SCSIDeviceOps []SCSIDeviceOperation
}

func NewSCSIDeviceOperation(fn api.CommandFunc, sa *SCSIServiceAction, pr uint8) SCSIDeviceOperation {
	return SCSIDeviceOperation{
		CommandPerformFunc: fn,
		ServiceAction:      sa,
		PRConflictBits:     pr,
	}
}

func BuildSenseData(cmd *api.SCSICommand, key byte, asc SCSISubError) {
	senseBuffer := cmd.SenseBuffer
	if senseBuffer == nil {
		senseBuffer = &bytes.Buffer{}
	}
	if cmd.Device.Attrs.SenseFormat {
		// descriptor format
		// current, not deferred
		senseBuffer.WriteByte(0x72)
		senseBuffer.WriteByte(key)
		senseBuffer.WriteByte((byte(asc) >> 8) & 0xff)
		senseBuffer.WriteByte(byte(asc) & 0xff)
		cmd.SenseLength = 8
	} else {
		// fixed format
		var length uint32 = 0xa
		// current, not deferred
		senseBuffer.WriteByte(0x70)
		senseBuffer.WriteByte(0x00)
		senseBuffer.WriteByte(key)
		for i := 0; i < 4; i++ {
			senseBuffer.WriteByte(0x00)
		}
		senseBuffer.WriteByte(byte(length))
		for i := 0; i < 4; i++ {
			senseBuffer.WriteByte(0x00)
		}
		senseBuffer.WriteByte((byte(asc) >> 8) & 0xff)
		senseBuffer.WriteByte(byte(asc) & 0xff)
		cmd.SenseLength = length + 8
	}
}

func getSCSIReadWriteOffset(scb []byte) uint64 {
	var off uint64
	var opcode = api.SCSICommandType(scb[0])

	switch opcode {
	case api.READ_6, api.WRITE_6:
		off = uint64((scb[1]&0x1f))<<16 + uint64(scb[2])<<8 + uint64(scb[3])
	case api.READ_10, api.PRE_FETCH_10, api.WRITE_10, api.VERIFY_10, api.WRITE_VERIFY, api.WRITE_SAME, api.SYNCHRONIZE_CACHE, api.READ_12, api.WRITE_12, api.VERIFY_12, api.WRITE_VERIFY_12:
		off = uint64(binary.BigEndian.Uint32(scb[2:]))
	case api.READ_16, api.PRE_FETCH_16, api.WRITE_16, api.ORWRITE_16, api.VERIFY_16, api.WRITE_VERIFY_16, api.WRITE_SAME_16, api.SYNCHRONIZE_CACHE_16, api.COMPARE_AND_WRITE:
		off = binary.BigEndian.Uint64(scb[2:])
	default:
	}

	return off
}

func getSCSIReadWriteCount(scb []byte) uint32 {
	var cnt uint32
	var opcode = api.SCSICommandType(scb[0])

	switch opcode {
	case api.READ_6, api.WRITE_6:
		cnt = uint32(scb[4])
		if cnt == 0 {
			cnt = 256
		}
	case api.READ_10, api.PRE_FETCH_10, api.WRITE_10, api.VERIFY_10, api.WRITE_VERIFY, api.WRITE_SAME, api.SYNCHRONIZE_CACHE:
		cnt = uint32(scb[7])<<8 | uint32(scb[8])
	case api.READ_12, api.WRITE_12, api.VERIFY_12, api.WRITE_VERIFY_12:
		cnt = binary.BigEndian.Uint32(scb[6:])
	case api.READ_16, api.PRE_FETCH_16, api.WRITE_16, api.ORWRITE_16, api.VERIFY_16, api.WRITE_VERIFY_16, api.WRITE_SAME_16, api.SYNCHRONIZE_CACHE_16:
		cnt = binary.BigEndian.Uint32(scb[10:])
	case api.COMPARE_AND_WRITE:
		cnt = uint32(scb[13])
	default:
	}

	return cnt
}
