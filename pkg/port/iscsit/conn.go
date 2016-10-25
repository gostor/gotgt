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
	"net"
	"sync"

	"github.com/gostor/gotgt/pkg/api"
)

const (
	CONN_STATE_FREE           = 0
	CONN_STATE_SECURITY       = 1
	CONN_STATE_SECURITY_AUTH  = 2
	CONN_STATE_SECURITY_DONE  = 3
	CONN_STATE_SECURITY_LOGIN = 4
	CONN_STATE_SECURITY_FULL  = 5
	CONN_STATE_LOGIN          = 6
	CONN_STATE_LOGIN_FULL     = 7
	CONN_STATE_FULL           = 8
	CONN_STATE_KERNEL         = 9
	CONN_STATE_CLOSE          = 10
	CONN_STATE_EXIT           = 11
	CONN_STATE_SCSI           = 12
	CONN_STATE_INIT           = 13
	CONN_STATE_START          = 14
	CONN_STATE_READY          = 15
)

var (
	DATAIN  byte = 0x01
	DATAOUT byte = 0x10
)

type iscsiConnection struct {
	state          int
	authState      int
	session        *ISCSISession
	sessionType    int
	sessionParam   []ISCSISessionParam
	tid            int
	CID            uint16
	rxIOState      int
	txIOState      int
	refcount       int
	conn           net.Conn
	initiator      string
	initiatorAlias string
	tpgt           uint16

	rxBuffer []byte
	txBuffer []byte
	req      *ISCSICommand
	resp     *ISCSICommand

	// StatSN - the status sequence number on this connection
	statSN uint32
	// ExpStatSN - the expected status sequence number on this connection
	expStatSN uint32
	// CmdSN - the command sequence number at the target
	cmdSN uint32
	// ExpCmdSN - the next expected command sequence number at the target
	expCmdSN uint32
	// MaxCmdSN - the maximum CmdSN acceptable at the target from this initiator
	maxCmdSN uint32

	rxTask *iscsiTask
	txTask *iscsiTask

	authMethod AuthMethod

	readLock *sync.RWMutex
}

type taskState int

const (
	taskPending taskState = 0
	taskSCSI    taskState = 1
)

type iscsiTask struct {
	tag   uint32
	conn  *iscsiConnection
	cmd   *ISCSICommand
	scmd  *api.SCSICommand
	state taskState

	offset     int
	r2tCount   int
	unsolCount int
	expR2TSN   int

	r2tSN uint32
}

func (c *iscsiConnection) init() {
	c.state = CONN_STATE_FREE
	c.refcount = 1
	c.readLock = new(sync.RWMutex)
	c.sessionParam = []ISCSISessionParam{}
	for _, param := range sessionKeys {
		c.sessionParam = append(c.sessionParam, ISCSISessionParam{Value: param.def})
	}
}

func (c *iscsiConnection) readData(size int) ([]byte, int, error) {
	var buf = make([]byte, size)
	length, err := c.conn.Read(buf)
	if err != nil {
		return nil, -1, err
	}
	return buf, length, nil
}

func (c *iscsiConnection) write(resp []byte) (int, error) {
	return c.conn.Write(resp)
}

func (c *iscsiConnection) close() {
	c.conn.Close()
}
