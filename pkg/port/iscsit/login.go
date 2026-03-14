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

	"github.com/gostor/gotgt/pkg/util"
)

var (
	iSCSILoginParamTextKV = []util.KeyValue{
		{Key: "HeaderDigest", Value: "None"},
		{Key: "DataDigest", Value: "None"},
		{Key: "ImmediateData", Value: "Yes"},
		{Key: "InitialR2T", Value: "Yes"},
		{Key: "MaxBurstLength", Value: "262144"},
		{Key: "FirstBurstLength", Value: "65536"},
		{Key: "MaxRecvDataSegmentLength", Value: "65536"},
		{Key: "DefaultTime2Wait", Value: "2"},
		{Key: "DefaultTime2Retain", Value: "0"},
		{Key: "MaxOutstandingR2T", Value: "1"},
		{Key: "IFMarker", Value: "No"},
		{Key: "OFMarker", Value: "No"},
		{Key: "DataPDUInOrder", Value: "Yes"},
		{Key: "DataSequenceInOrder", Value: "Yes"}}
)

type iSCSILoginStage int

const (
	SecurityNegotiation         iSCSILoginStage = 0
	LoginOperationalNegotiation                 = 1
	FullFeaturePhase                            = 3
)

func (s iSCSILoginStage) String() string {
	switch s {
	case SecurityNegotiation:
		return "Security Negotiation"
	case LoginOperationalNegotiation:
		return "Login Operational Negotiation"
	case FullFeaturePhase:
		return "Full Feature Phase"
	}
	return "Unknown Stage"
}

func loginKVDeclare(conn *iscsiConnection, negoKV []util.KeyValue) []util.KeyValue {
	negoKV = append(negoKV, util.KeyValue{Key: "TargetPortalGroupTag",
		Value: numberKeyInConv(uint(conn.loginParam.tpgt))})
	negoKV = append(negoKV, util.KeyValue{Key: "MaxRecvDataSegmentLength",
		Value: numberKeyInConv(sessionKeys["MaxRecvDataSegmentLength"].def)})
	return negoKV
}

func stringsContains(s []string, p string) bool {
	for _, q := range s {
		if q == p {
			return true
		}
	}
	return false
}

func (conn *iscsiConnection) processSecurityData() error {
	securityKV := util.ParseKVText(conn.req.RawData)

	for key, val := range securityKV {
		if key == "AuthMethod" {
			// It can be a list.
			vals := strings.Split(val, ",")
			if !stringsContains(vals, "None") {
				// TODO: respond with Reject message, rather
				// than terminating TCP connection.
				return fmt.Errorf("client requesting AuthMethod:%s, only support None", val)
			}
			conn.loginParam.tgtNSG = LoginOperationalNegotiation
			conn.loginParam.tgtTrans = true
			conn.loginParam.authMethod = AuthNone
		} else if key == "TargetName" {
			conn.loginParam.target = val
		} else if key == "InitiatorName" {
			conn.loginParam.initiator = val
		}
	}

	return nil
}

func (conn *iscsiConnection) processLoginData() ([]util.KeyValue, error) {
	var (
		uintVal    uint
		ok         bool
		defSessKey *iscsiSessionKeys
		negoKV     []util.KeyValue
		kvChanges  int
	)
	loginKV := util.ParseKVText(conn.req.RawData)

	for key, val := range loginKV {
		// The MaxRecvDataSegmentLength of initiator
		// is the MaxXmitDataSegmentLength of target
		if key == "MaxRecvDataSegmentLength" {
			defSessKey, ok = sessionKeys["MaxXmitDataSegmentLength"]
			uintVal, ok = defSessKey.conv(val)
			conn.loginParam.sessionParam[defSessKey.idx].Value = uintVal
			continue
		}

		if key == "InitiatorName" {
			conn.loginParam.initiator = val
			continue
		} else if key == "InitiatorAlias" {
			conn.loginParam.initiatorAlias = val
			continue
		} else if key == "TargetName" {
			conn.loginParam.target = val
			continue
		} else if key == "SessionType" {
			if val == "Normal" {
				conn.loginParam.sessionType = SESSION_NORMAL
			} else {
				conn.loginParam.sessionType = SESSION_DISCOVERY
			}
			continue
		}

		defSessKey, ok = sessionKeys[key]
		if ok {
			uintVal, ok = defSessKey.conv(val)

			//hack here
			if key == "HeaderDigest" || key == "DataDigest" {
				if uintVal == DIGEST_ALL {
					uintVal = DIGEST_NONE
				}
			}
			if ok {
				if defSessKey.constValue {
					//the Negotiation Key cannot be changed! Uses Target default key
					if uintVal != defSessKey.def {
						kvChanges++
					}
					negoKV = append(negoKV, util.KeyValue{Key: key, Value: defSessKey.inConv(defSessKey.def)})
				} else {
					if (uintVal >= defSessKey.min) && (uintVal <= defSessKey.max) {
						conn.loginParam.sessionParam[defSessKey.idx].Value = uintVal
						negoKV = append(negoKV, util.KeyValue{Key: key, Value: defSessKey.inConv(uintVal)})
					} else {
						// the value out of the acceptable range, Uses target default key
						negoKV = append(negoKV, util.KeyValue{Key: key, Value: defSessKey.inConv(defSessKey.def)})
						kvChanges++
					}
				}
			}
		} else {
			//Unknown Key, reject it
			return negoKV, fmt.Errorf("Unknowen Nego KV [%s:%s]", key, val)
		}
	}

	if kvChanges == 0 {
		if (conn.loginParam.iniNSG == FullFeaturePhase) && conn.loginParam.iniTrans {
			conn.loginParam.tgtNSG = FullFeaturePhase
			conn.loginParam.tgtTrans = true
		} else {
			//Currently, we just reject these kind of cases
			return negoKV, fmt.Errorf("reject CSG=%s,NSG=%s,trans=%t",
				conn.loginParam.iniCSG, conn.loginParam.iniNSG, conn.loginParam.iniTrans)
		}
	} else {
		conn.loginParam.tgtNSG = FullFeaturePhase
		conn.loginParam.tgtTrans = true
	}
	return negoKV, nil
}

type iscsiLoginParam struct {
	paramInit bool

	iniCSG   iSCSILoginStage
	iniNSG   iSCSILoginStage
	iniTrans bool
	iniCont  bool

	tgtCSG   iSCSILoginStage
	tgtNSG   iSCSILoginStage
	tgtTrans bool
	tgtCont  bool

	sessionType  int
	sessionParam ISCSISessionParamList
	keyDeclared  bool

	initiator      string
	initiatorAlias string
	target         string
	targetAlias    string

	tpgt uint16
	isid uint64
	tsih uint16

	authMethod AuthMethod
}

func (m *ISCSICommand) loginRespBytes() []byte {
	// rfc7143 11.13 - BHS 48 bytes + data (4-byte aligned)
	rawDataLen := len(m.RawData)
	padding := (4 - rawDataLen%4) % 4
	buf := make([]byte, 48+rawDataLen+padding)

	// byte 0: Opcode
	buf[0] = byte(OpLoginResp)
	var b byte
	if m.Transit {
		b |= 0x80
	}
	if m.Cont {
		b |= 0x40
	}
	b |= byte(m.CSG&0xff) << 2
	b |= byte(m.NSG & 0xff)
	// byte 1
	buf[1] = b

	// byte 2: version-max, byte 3: version-active
	// bytes 4-7: data segment length (24-bit)
	buf[5] = byte(rawDataLen >> 16)
	buf[6] = byte(rawDataLen >> 8)
	buf[7] = byte(rawDataLen)
	// bytes 8-13: ISID (6 bytes) - lower 6 bytes of uint64
	buf[8] = byte(m.ISID >> 40)
	buf[9] = byte(m.ISID >> 32)
	buf[10] = byte(m.ISID >> 24)
	buf[11] = byte(m.ISID >> 16)
	buf[12] = byte(m.ISID >> 8)
	buf[13] = byte(m.ISID)
	// bytes 14-15: TSIH (2 bytes)
	buf[14] = byte(m.TSIH >> 8)
	buf[15] = byte(m.TSIH)
	// bytes 16-19: TaskTag
	util.MarshalUint32To(buf[16:], m.TaskTag)
	// bytes 20-23: reserved
	// bytes 24-27: StatSN
	util.MarshalUint32To(buf[24:], m.StatSN)
	// bytes 28-31: ExpCmdSN
	util.MarshalUint32To(buf[28:], m.ExpCmdSN)
	// bytes 32-35: MaxCmdSN
	util.MarshalUint32To(buf[32:], m.MaxCmdSN)
	// bytes 36: StatusClass, 37: StatusDetail
	buf[36] = byte(m.StatusClass)
	buf[37] = byte(m.StatusDetail)
	// bytes 38-47: reserved
	// Copy data
	copy(buf[48:], m.RawData)
	// padding bytes are already zero
	return buf
}
