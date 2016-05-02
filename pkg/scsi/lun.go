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

import "github.com/gostor/gotgt/pkg/api"

type SCSILuOps struct {
	*api.SCSILu

	DeviceProtocol SCSIDeviceProtocol
	Storage        *BackingStore
	Target         *api.SCSITarget
	Attrs          api.SCSILuPhyAttribute

	// function handler for command performing and finishing
	PerformCommand CommandFunc
	FinishCommand  func(*api.SCSITarget, *api.SCSICommand)
}

func luPreventRemoval(lu *api.SCSILu) bool {
	// TODO
	return false
}
