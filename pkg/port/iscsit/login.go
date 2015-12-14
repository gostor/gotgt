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

package iscsit

import "bytes"

func (m *Message) loginRespBytes() []byte {
	// rfc7143 11.13
	buf := &bytes.Buffer{}
	// byte 0
	buf.WriteByte(byte(OpLoginResp))
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
	buf.WriteByte(b)

	b = 0
	buf.WriteByte(b)                                     // version-max
	buf.WriteByte(b)                                     // version-active
	buf.WriteByte(b)                                     // ahsLen
	buf.Write(MarshalUint64(uint64(len(m.RawData)))[5:]) // data segment length, no padding
	buf.Write(MarshalUint64(m.ISID)[2:])
	buf.Write(MarshalUint64(uint64(m.TSIH))[6:])
	buf.Write(MarshalUint64(uint64(m.TaskTag))[4:])
	buf.WriteByte(b)
	buf.WriteByte(b)
	buf.WriteByte(b)
	buf.WriteByte(b) // "reserved"
	buf.Write(MarshalUint64(uint64(m.StatSN))[4:])
	buf.Write(MarshalUint64(uint64(m.ExpCmdSN))[4:])
	buf.Write(MarshalUint64(uint64(m.MaxCmdSN))[4:])
	buf.WriteByte(byte(m.StatusClass))
	buf.WriteByte(byte(m.StatusDetail))
	buf.WriteByte(b)
	buf.WriteByte(b) // "reserved"
	var bs [8]byte
	buf.Write(bs[:])
	rd := m.RawData
	for len(rd)%4 != 0 {
		rd = append(rd, 0)
	}
	buf.Write(rd)
	return buf.Bytes()
}

type Stage int

const (
	SecurityNegotiation         Stage = 0
	LoginOperationalNegotiation       = 1
	FullFeaturePhase                  = 3
)

func (s Stage) String() string {
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
