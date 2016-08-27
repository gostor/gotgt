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
	"os"

	"github.com/gostor/gotgt/pkg/api"
)

type BaseBackingStore struct {
	Name            string
	DataSize        int
	OflagsSupported int
}

type BackingStoreFunc func() (api.BackingStore, error)

var registeredPlugins = map[string](BackingStoreFunc){}

func RegisterBackingStore(name string, f BackingStoreFunc) {
	registeredPlugins[name] = f
}

func NewBackingStore(name string) (api.BackingStore, error) {
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

func (fake *fakeBackingStore) Open(dev *api.SCSILu, path string) (*os.File, error) {
	return nil, nil
}

func (fake *fakeBackingStore) Close(dev *api.SCSILu) error {
	return nil
}

func (fake *fakeBackingStore) Init(dev *api.SCSILu, Opts string) error {
	return nil
}

func (fake *fakeBackingStore) Exit(dev *api.SCSILu) error {
	return nil
}

func (fake *fakeBackingStore) CommandSubmit(cmd *api.SCSICommand) error {
	return nil
}
