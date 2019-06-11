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
	"fmt"
	"strconv"
	"sync"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/config"
)

type BackendType string

type SCSILUMap struct {
	mutex sync.RWMutex
	// use UUID as the key for all LUs
	AllDevices api.LUNMap
	// use target name as the key for target's LUN map
	TargetsLUNMap map[string]api.LUNMap
}

var globalSCSILUMap = SCSILUMap{AllDevices: make(api.LUNMap), TargetsLUNMap: make(map[string]api.LUNMap)}

type LUNMapping struct {
	TargetName string
	LUN        uint64
	DeviceID   uint64
}

func mappingLUN(lm LUNMapping) {
	device := globalSCSILUMap.AllDevices[lm.DeviceID]
	lunMap := globalSCSILUMap.TargetsLUNMap[lm.TargetName]
	if lunMap == nil {
		globalSCSILUMap.TargetsLUNMap[lm.TargetName] = make(api.LUNMap)
		lunMap = globalSCSILUMap.TargetsLUNMap[lm.TargetName]
	}
	lunMap[lm.LUN] = device
}

func GetLU(tgtName string, LUN uint64) *api.SCSILu {
	globalSCSILUMap.mutex.RLock()
	defer globalSCSILUMap.mutex.RUnlock()

	lunMap := globalSCSILUMap.TargetsLUNMap[tgtName]
	lun := lunMap[LUN]

	return lun
}

func GetTargetLUNMap(tgtName string) api.LUNMap {
	globalSCSILUMap.mutex.RLock()
	defer globalSCSILUMap.mutex.RUnlock()

	lunMap := globalSCSILUMap.TargetsLUNMap[tgtName]
	return lunMap
}

func AddBackendStorage(bs config.BackendStorage) error {
	globalSCSILUMap.mutex.Lock()
	defer globalSCSILUMap.mutex.Unlock()
	_, ok := globalSCSILUMap.AllDevices[bs.DeviceID]
	if ok {
		return fmt.Errorf("device %q already exists", bs.DeviceID)
	}

	lu, err := NewSCSILu(&bs)
	if err != nil {
		return fmt.Errorf("Init SCSI LU map error: %v", err)
	}
	globalSCSILUMap.AllDevices[bs.DeviceID] = lu
	return nil
}

func AddLUNMapping(m LUNMapping) error {
	globalSCSILUMap.mutex.Lock()
	defer globalSCSILUMap.mutex.Unlock()
	mappingLUN(m)
	// Init SCSISimpleReservationOperator
	op := GetSCSIReservationOperator()
	if simpleOp, ok := op.(*SCSISimpleReservationOperator); ok {
		simpleOp.InitLUReservation(m.TargetName, m.DeviceID)
	}
	return nil
}

func InitSCSILUMap(config *config.Config) error {
	for _, bs := range config.Storages {
		if err := AddBackendStorage(bs); err != nil {
			return err
		}
	}

	for tgtName, tgt := range config.ISCSITargets {
		for lunstr, deviceID := range tgt.LUNs {
			lun, err := strconv.ParseUint(lunstr, 10, 64)
			if err != nil {
				return fmt.Errorf("LU Number must be a number")
			}
			m := LUNMapping{DeviceID: deviceID, LUN: lun, TargetName: tgtName}
			AddLUNMapping(m)
		}
	}
	return nil
}
