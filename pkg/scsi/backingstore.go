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

import "fmt"

type BaseBackingStore struct {
	Name            string
	DataSize        int
	OflagsSupported int
}

type BackingStore interface {
	Open(dev *SCSILu, path string, fd *int, size *uint64) error
	Close(dev *SCSILu) error
	Init(dev *SCSILu, Opts string) error
	Exit(dev *SCSILu) error
	CommandSubmit(cmd *SCSICommand) error
}

type BackingStoreFunc func() (BackingStore, error)

var registeredPlugins = map[name](BackingStoreFunc){}

func RegisterBackingStore(name string, f BackingStoreFunc) {
	registeredPlugins[name] = f
}

func NewBackingStore(name string) (BackingStore, error) {
	if name == "" {
		return nil, nil
	}
	f, ok := registeredPlugins[name]
	if !ok {
		return nil, fmt.Errorf("BackingStore %s is not found.", name)
	}
	return f()
}

type fakeBackingStore struct {
	BaseBackingStore
}

func (fake *fakeBackingStore) Open(dev *SCSILu, path string, fd *int, size *uint64) error {
	return nil
}

func (fake *fakeBackingStore) Close(dev *SCSILu) error {
	return nil
}

func (fake *fakeBackingStore) Init(dev *SCSILu, Opts string) error {
	return nil
}

func (fake *fakeBackingStore) Exit(dev *SCSILu) error {
	return nil
}

func (fake *fakeBackingStore) CommandSubmit(cmd *SCSICommand) error {
	return nil
}
