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

package scsi

import (
	"fmt"

	"github.com/golang/glog"
)

type SCSITargetState int

var (
	TargetOnline SCSITargetState = 1
	TargetReady  SCSITargetState = 2
)

const (
	PR_SPECIAL = (1 << 5)
	PR_WE_FA   = (1 << 4)
	PR_EA_FA   = (1 << 3)
	PR_RR_FR   = (1 << 2)
	PR_WE_FN   = (1 << 1)
	PR_EA_FN   = (1 << 0)
)

type ITNexus struct {
	ID       uint64
	Ctime    uint64
	Commands []SCSICommand
	Target   *SCSITarget
	Host     int
	Info     string
}

type ITNexusLuInfo struct {
	Lu      *SCSILu
	ID      uint64
	Prevent int
}

type SCSITarget struct {
	Name    string
	TID     int
	LID     int
	State   SCSITargetState
	Devices []SCSILu
	ITNexus []ITNexus
}

func deviceReserve(cmd *SCSICommand) error {
	var lu *SCSILu
	for _, dev := range cmd.Target.Devices {
		if dev.Lun == cmd.Device.Lun {
			lu = &dev
			break
		}
	}
	if lu == nil {
		glog.Errorf("invalid target and lun %d %s", cmd.Target.TID, cmd.Device.Lun)
		return nil
	}

	if lu.ReserveID != 0 && lu.ReserveID != cmd.CommandITNID {
		glog.Errorf("already reserved %d, %d", lu.ReserveID, cmd.CommandITNID)
		return fmt.Errorf("already reserved")
	}
	lu.ReserveID = cmd.CommandITNID
	return nil
}

func deviceRelease(tid int, itn, lun uint64, force bool) error {
	// TODO
	return nil
}
