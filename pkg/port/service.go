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

package port

import (
	"fmt"

	"github.com/gostor/gotgt/pkg/scsi"
)

type SCSITargetService interface {
	Run() error
	NewTarget(string, []string) (SCSITargetDriver, error)
	AddNewPortal(string, string) error
}

type TargetServiceFunc func(*scsi.SCSITargetService) (SCSITargetService, error)

var registeredPlugins = map[string](TargetServiceFunc){}

func RegisterTargetService(name string, f TargetServiceFunc) {
	registeredPlugins[name] = f
}

func NewTargetService(targetDriverName string, s *scsi.SCSITargetService) (SCSITargetService, error) {
	if targetDriverName == "" {
		return nil, nil
	}
	targetInitFunc, ok := registeredPlugins[targetDriverName]
	if !ok {
		return nil, fmt.Errorf("SCSI target driver %s is not found.", targetDriverName)
	}
	return targetInitFunc(s)
}
