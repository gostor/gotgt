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

// Target Driver Interface
package scsi

var SCSITargetDriverState int

const (
	// just registered
	SCSI_DRIVER_REGD = iota
	// initialized ok
	SCSI_DRIVER_INIT
	// failed to initialize
	SCSI_DRIVER_ERR
	// exited
	SCSI_DRIVER_EXIT
)

type SCSITargetDriver struct {
	Name       string
	State      SCSITargetDriverState
	DefaultBST string
	Targets    []*SCSITarget
}

type SCSITargetDriverOps interface {
	Init() error
	Exit() error

	CreateTarget(target *SCSITarget) error
	DestroyTarget(target *SCSITarget) error
	CreatePortal(name string) error
	DestroyPortal(name string) error
	CreateLu(lu *SCSILu) error

	GetLun(lun uint8) (uint64, error)
	CommandNotify(nid uint64, result int, cmd *SCSICommand) error
}

var fakeSCSITargetDriver SCSITargetDriver

func (fake *fakeSCSITargetDriver) Init() error {
	return nil
}

func (fake *fakeSCSITargetDriver) Exit() error {
	return nil
}

func (fake *fakeSCSITargetDriver) CreateTarget(target *SCSITarget) error {
	return nil
}

func (fake *fakeSCSITargetDriver) DestroyTarget(target *SCSITarget) error {
	return nil
}

func (fake *fakeSCSITargetDriver) CreatePortal(name string) error {
	return nil
}

func (fake *fakeSCSITargetDriver) DestroyPortal(name string) error {
	return nil
}

func (fake *fakeSCSITargetDriver) CreateLu(lu *SCSILu) error {
	return nil
}

func (fake *fakeSCSITargetDriver) GetLun(lun uint8) (uint64, error) {
	return 0, nil
}
func (fake *fakeSCSITargetDriver) CommandNotify(nid uint64, result int, cmd *SCSICommand) error {
	return nil
}
