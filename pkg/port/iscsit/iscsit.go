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

// iSCSI Target Driver
package iscsit

import (
	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/util"
)

type ISCSIDiscoveryMethod string

var (
	ISCSIDiscoverySendTargets  ISCSIDiscoveryMethod = "sendtargets"
	ISCSIDiscoveryStaticConfig ISCSIDiscoveryMethod = "static"
	ISCSIDiscoveryISNS         ISCSIDiscoveryMethod = "isns"
)

type ISCSIRedirectInfo struct {
	Address  string
	Port     int
	Reason   uint8
	Callback string
}

type ISCSITarget struct {
	*api.SCSITarget
	api.SCSITargetDriverCommon

	Sessions     []*ISCSISession
	SessionParam []ISCSISessionParam
	Alias        string
	MaxSessions  int
	RedirectInfo ISCSIRedirectInfo
	Rdma         int
	NopInterval  int
	NopCount     int
}

func NewISCSITarget(target *api.SCSITarget) *ISCSITarget {
	return &ISCSITarget{
		SCSITarget: target,
	}
}

func (tgt *ISCSITarget) Init() error {
	return nil
}

func (tgt *ISCSITarget) Exit() error {
	return nil
}

func (tgt *ISCSITarget) CreateTarget(target *api.SCSITarget) error {
	return nil
}

func (tgt *ISCSITarget) DestroyTarget(target *api.SCSITarget) error {
	return nil
}

func (tgt *ISCSITarget) CreatePortal(name string) error {
	return nil
}

func (tgt *ISCSITarget) DestroyPortal(name string) error {
	return nil
}

func (tgt *ISCSITarget) CreateLu(lu *api.SCSILu) error {
	return nil
}

func (tgt *ISCSITarget) GetLu(lun uint8) (uint64, error) {
	return 0, nil
}
func (tgt *ISCSITarget) CommandNotify(nid uint64, result int, cmd *api.SCSICommand) error {
	return nil
}
func (tgt *ISCSITarget) ProcessCommand(buf []byte) ([]byte, error) {
	b := make([]byte, 48) // TODO: sync.Pool
	b = buf[0:48]
	m, err := parseHeader(b)
	if err != nil {
		return nil, err
	}
	m.RawHeader = b
	if m.DataLen > 0 {
		m.RawData = buf[48:m.DataLen]
	}
	resp := &ISCSICommand{}
	switch m.OpCode {
	case OpLoginReq:
		resp = &ISCSICommand{
			OpCode:   OpLoginResp,
			Transit:  true,
			NSG:      FullFeaturePhase,
			StatSN:   m.ExpStatSN,
			TaskTag:  m.TaskTag,
			ExpCmdSN: m.CmdSN,
			MaxCmdSN: m.CmdSN,
			RawData: util.MarshalKVText(map[string]string{
				"HeaderDigest": "None",
				"DataDigest":   "None",
			}),
		}
		break
	case OpSCSICmd:
		resp = &ISCSICommand{
			OpCode:   OpSCSIResp,
			Final:    true,
			StatSN:   m.ExpStatSN,
			TaskTag:  m.TaskTag,
			ExpCmdSN: m.CmdSN + 1,
			MaxCmdSN: m.CmdSN + 10,
		}
		switch api.SCSICommandType(m.CDB[0]) {
		case api.TEST_UNIT_READY:
			// test unit ready
			resp.Status = api.SAM_STAT_GOOD
			resp.SCSIResponse = 0x01
			break
		case api.READ_CAPACITY:
			resp.OpCode = OpSCSIIn
			resp.HasStatus = true
			var data []byte
			data = append(data, MarshalUint64(uint64(0))[4:]...)
			data = append(data, MarshalUint64(uint64(0))[4:]...)
			resp.RawData = data
			break
		case api.SERVICE_ACTION_IN:
			resp.OpCode = OpSCSIIn
			resp.HasStatus = true
			sa := m.CDB[1] & 0x1f
			switch sa {
			case 0x10:
				c := &Capacity{}
				resp.RawData = c.bytes()
			}
			break
		case api.INQUIRY:
			resp.OpCode = OpSCSIIn
			resp.HasStatus = true
			alloc := int(ParseUint(m.CDB[3:5]))
			inq := &InquiryData{
				Vendor:        [8]byte{'1', '1', 'c', 'a', 'n', 's'},
				Product:       [16]byte{'c', 'o', 'f', 'f', 'e', 'e'},
				RevisionLevel: [4]byte{'1', '.', '0'},
				SerialNumber:  52,
			}

			if len(inq.bytes()) >= alloc {
				resp.RawData = inq.bytes()[:alloc]
			} else {
				resp.RawData = inq.bytes()
			}
			break
		default:
			break
		}
	}
	b1 := resp.Bytes()
	return b1, nil
}
