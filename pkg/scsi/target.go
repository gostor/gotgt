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
	"github.com/gostor/gotgt/pkg/api"
)

func (s *SCSITargetService) NewSCSITarget(tid int, driverName, name string) (*api.SCSITarget, error) {
	// verify the target ID

	// verify the target's Name

	// verify the low level driver
	var target = &api.SCSITarget{
		Name:    name,
		TID:     tid,
		Devices: []*api.SCSILu{},
	}
	lun, err := NewSCSILu(0, target)
	if err != nil {
		glog.Errorf("fail to create LU: %v", err)
		return nil, err
	}
	s.mutex.Lock()
	target.Devices = append(target.Devices, lun)
	s.Targets = append(s.Targets, target)
	s.mutex.Unlock()
	return target, nil
}

func deviceReserve(cmd *api.SCSICommand) error {
	var lu *api.SCSILu
	for _, dev := range cmd.Target.Devices {
		if dev.Lun == cmd.Device.Lun {
			lu = dev
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
