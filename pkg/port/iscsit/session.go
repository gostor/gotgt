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

import "crypto/rand"

type ISCSISessionParam struct {
	State int
	Value uint
}

// Session is an iSCSI session.
type ISCSISession struct {
	Refcount       int
	Initiator      string
	InitiatorAlias string
	Target         *ISCSITarget
	Isid           uint64
	Tsih           uint16
	// only one connection per session
	Connections        []*ISCSIConnection
	Commands           []*ISCSICommand
	PendingCommands    []*ISCSICommand
	ExpectionCommandSN uint32
	MaxQueueCommand    uint32
	SessionParam       []ISCSISessionParam
	Info               string
	Rdma               int
}

type ISCSIHeader struct {
}

type ISCSIPdu struct {
	Bhs      ISCSIHeader
	AhsSize  uint
	DataSize uint
}

type ISCSIConnection struct {
	State     int
	RxIostate int
	TxIostate int
	Refcount  int

	Session *ISCSISession

	TID                int
	CID                int
	Auth               AuthMethod
	StatSN             uint32
	ExpectionStatSN    uint32
	CommandSN          uint32
	ExpectionCommandSN uint32
	MaxCommandSN       uint32
	Request            ISCSIPdu
	Response           ISCSIPdu
}

// New creates a new session.
func NewISCSISession() (*ISCSISession, error) {
	var tsih uint16
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	tsih += uint16(b[0]) << 8
	tsih += uint16(b[1])

	return &ISCSISession{
		Tsih: tsih,
	}, nil
}
