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

// iSCSI Target Driver
package iscsit

import "github.com/gostor/gotgt/pkg/api"

const (
	IOSTATE_FREE = iota

	IOSTATE_RX_BHS
	IOSTATE_RX_INIT_AHS
	IOSTATE_RX_AHS
	IOSTATE_RX_INIT_HDIGEST
	IOSTATE_RX_HDIGEST
	IOSTATE_RX_CHECK_HDIGEST
	IOSTATE_RX_INIT_DATA
	IOSTATE_RX_DATA
	IOSTATE_RX_INIT_DDIGEST
	IOSTATE_RX_DDIGEST
	IOSTATE_RX_CHECK_DDIGEST
	IOSTATE_RX_END

	IOSTATE_TX_BHS
	IOSTATE_TX_INIT_AHS
	IOSTATE_TX_AHS
	IOSTATE_TX_INIT_HDIGEST
	IOSTATE_TX_HDIGEST
	IOSTATE_TX_INIT_DATA
	IOSTATE_TX_DATA
	IOSTATE_TX_INIT_DDIGEST
	IOSTATE_TX_DDIGEST
	IOSTATE_TX_END
)

var ISCSI_OPCODE_MASK = 0x3F

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
	api.SCSITarget
	api.SCSITargetDriverCommon
	Portals      map[string]struct{}
	Sessions     []*ISCSISession
	SessionParam []ISCSISessionParam
	Alias        string
	MaxSessions  int
	RedirectInfo ISCSIRedirectInfo
	Rdma         int
	NopInterval  int
	NopCount     int
}

func newISCSITarget(target *api.SCSITarget) *ISCSITarget {
	return &ISCSITarget{
		SCSITarget: *target,
		Portals:    make(map[string]struct{}),
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
