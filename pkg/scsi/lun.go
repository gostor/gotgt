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

type SCSILuPhyAttribute struct {
	SCSIID          string
	SCSISN          string
	NumID           uint64
	VendorID        string
	ProductID       string
	ProductRev      string
	VersionDesction []uint16
	// Peripheral device type
	DeviceType uint
	// Peripheral Qualifier
	Qualifier bool
	// Removable media
	Removable bool
	// Read Only media
	Readonly bool
	// Software Write Protect
	SWP bool
	// Use thin-provisioning for this LUN
	Thinprovisioning bool
	// Logical Unit online
	Online bool
	// Descrptor format sense data supported
	SenseFormat bool
	// Logical blocks per physical block exponent
	Lbppbe int
	// Do not update it automatically when the backing file changes
	NoLbppbe int
	// Lowest aligned LBA
	LowestAlignedLBA int
}

type SCSILu struct {
	FD             int
	Address        uint64
	Size           uint64
	Lun            uint64
	Path           string
	BsoFlags       int
	BlockShift     uint
	ReserveID      uint64
	DeviceProtocol SCSIDeviceProtocol
	Storage        *BackingStore
	Target         *SCSITarget
	Attrs          SCSILuPhyAttribute

	// function handler for command performing and finishing
	PerformCommand CommandFunc
	FinishCommand  func(*SCSITarget, *SCSICommand)
}

func luPreventRemoval(lu *SCSILu) bool {
	// TODO
	return false
}
