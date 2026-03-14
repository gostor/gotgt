package iscsit

import (
	"github.com/gostor/gotgt/pkg/util"
)

func (m *ISCSICommand) logoutRespBytes() []byte {
	// rfc7143 11.10 - Fixed 48 bytes
	buf := make([]byte, 48)
	buf[0] = byte(OpLogoutResp)
	buf[1] = 0x80
	// buf[2] = response (0)
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
