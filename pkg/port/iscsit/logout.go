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

func (m *Message) logoutRespBytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(byte(OpLogoutResp))
	buf.WriteByte(0x80)
	buf.WriteByte(0x00) // response
	buf.WriteByte(0x00)
	for i := 4; i < 16; i++ {
		buf.WriteByte(0x00)
	}
	buf.Write(MarshalUint64(uint64(m.TaskTag))[4:])
	for i := 20; i < 24; i++ {
		buf.WriteByte(0x00)
	}
	buf.Write(MarshalUint64(uint64(m.StatSN))[4:])
	buf.Write(MarshalUint64(uint64(m.ExpCmdSN))[4:])
	buf.Write(MarshalUint64(uint64(m.MaxCmdSN))[4:])
	for i := 36; i < 48; i++ {
		buf.WriteByte(0x00)
	}
	return buf.Bytes()
}
