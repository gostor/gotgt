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

package scsi

import (
	"errors"
	"strings"

	"github.com/gostor/gotgt/pkg/api"
)

/*
 * path format <protocol>:/absolute/file/path
 */

func NewSCSILu(device_uuid uint64, path string, online bool) (*api.SCSILu, error) {

	pathinfo := strings.SplitN(path, ":", 2)
	if len(pathinfo) < 2 {
		return nil, errors.New("invalid device path string")
	}
	backendType := pathinfo[0]
	backendPath := pathinfo[1]

	sbc := NewSBCDevice(api.TYPE_DISK)
	backing, err := NewBackingStore(backendType)
	if err != nil {
		return nil, err
	}

	var lu = &api.SCSILu{
		PerformCommand: luPerformCommand,
		DeviceProtocol: sbc,
		Storage:        backing,
		BlockShift:     api.DefaultBlockShift,
	}

	err = backing.Open(lu, backendPath)
	if err != nil {
		return nil, err
	}
	lu.Size = backing.Size(lu)
	lu.DeviceProtocol.InitLu(lu)
	lu.Attrs.Online = online
	lu.Attrs.Lbppbe = 3
	return lu, nil
}

func NewLUN0() *api.SCSILu {

	sbc := NewSBCDevice(api.TYPE_UNKNOWN)
	backing, _ := NewBackingStore("null")
	var lu = &api.SCSILu{
		PerformCommand: luPerformCommand,
		DeviceProtocol: sbc,
		Storage:        backing,
		BlockShift:     api.DefaultBlockShift,
	}

	lu.Size = backing.Size(lu)
	lu.DeviceProtocol.InitLu(lu)
	lu.Attrs.Online = false
	lu.Attrs.Lbppbe = 3
	return lu
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
