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
	Sessions     []*ISCSISession
	SessionParam []ISCSISessionParam
	TID          int
	Alias        string
	MaxSessions  int
	RedirectInfo ISCSIRedirectInfo
	Rdma         int
	NopInterval  int
	NopCount     int
}

type ISCSITargetDriver struct {
	SCSITargetDriver
}

func (tgt *ISCSITargetDriver) Init() error {
	return nil
}

func (tgt *ISCSITargetDriver) Exit() error {
	return nil
}

func (tgt *ISCSITargetDriver) CreateTarget(target *SCSITarget) error {
	return nil
}

func (tgt *ISCSITargetDriver) DestroyTarget(target *SCSITarget) error {
	return nil
}

func (tgt *ISCSITargetDriver) CreatePortal(name string) error {
	return nil
}

func (tgt *ISCSITargetDriver) DestroyPortal(name string) error {
	return nil
}

func (tgt *ISCSITargetDriver) CreateLu(lu *SCSILu) error {
	return nil
}

func (tgt *ISCSITargetDriver) GetLun(lun uint8) (uint64, error) {
	return 0, nil
}
func (tgt *ISCSITargetDriver) CommandNotify(nid uint64, result int, cmd *SCSICommand) error {
	return nil
}
