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
	"os"

	"github.com/gostor/gotgt/pkg/api"
)

func NewSCSILu(lun uint64, target *api.SCSITarget) (*api.SCSILu, error) {
	sbc := NewSBCDevice()
	backing, err := NewBackingStore("file")
	if err != nil {
		return nil, err
	}
	var lu = &api.SCSILu{
		Lun:            lun,
		Target:         target,
		PerformCommand: luPerformCommand,
		DeviceProtocol: sbc,
		Storage:        backing,
		BlockShift:     0,
		Size:           1024 * 1024 * 10,
	}
	// hack this
	if _, err = os.Stat("/var/tmp/disk.img"); err != nil && os.IsExist(err) {
		panic(err)
	}
	f, err := backing.Open(lu, "/var/tmp/disk.img")
	if err != nil {
		return nil, err
	}
	lu.File = f
	lu.DeviceProtocol.InitLu(lu)
	lu.Attrs.Online = true
	return lu, nil
}

func luPerformCommand(tid int, cmd *api.SCSICommand) api.SAMStat {
	op := int(cmd.SCB.Bytes()[0])
	fn := cmd.Device.DeviceProtocol.PerformCommand(op)
	if fn != nil {
		fnop := fn.(SCSIDeviceOperation)
		// host := cmd.ITNexus.Host
		host := 0
		return fnop.CommandPerformFunc(host, cmd)
	}
	return api.SAMStatGood
}

func luPreventRemoval(lu *api.SCSILu) bool {
	// TODO
	return false
}
