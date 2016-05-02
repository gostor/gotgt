package port

import (
	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/port/iscsit"
)

type SCSITargetDriver interface {
	Init() error
	Exit() error

	CreateTarget(target *api.SCSITarget) error
	DestroyTarget(target *api.SCSITarget) error
	CreatePortal(name string) error
	DestroyPortal(name string) error
	CreateLu(lu *api.SCSILu) error
	GetLu(lun uint8) (uint64, error)

	ProcessCommand(buf []byte) ([]byte, error)
	CommandNotify(nid uint64, result int, cmd *api.SCSICommand) error
}

type fakeSCSITargetDriver struct {
	api.SCSITargetDriverCommon
}

func (fake *fakeSCSITargetDriver) Init() error {
	return nil
}

func (fake *fakeSCSITargetDriver) Exit() error {
	return nil
}

func (fake *fakeSCSITargetDriver) CreateTarget(target *api.SCSITarget) error {
	return nil
}

func (fake *fakeSCSITargetDriver) DestroyTarget(target *api.SCSITarget) error {
	return nil
}

func (fake *fakeSCSITargetDriver) CreatePortal(name string) error {
	return nil
}

func (fake *fakeSCSITargetDriver) DestroyPortal(name string) error {
	return nil
}

func (fake *fakeSCSITargetDriver) CreateLu(lu *api.SCSILu) error {
	return nil
}

func (fake *fakeSCSITargetDriver) GetLun(lun uint8) (uint64, error) {
	return 0, nil
}
func (fake *fakeSCSITargetDriver) CommandNotify(nid uint64, result int, cmd *api.SCSICommand) error {
	return nil
}
func (fake *fakeSCSITargetDriver) ProcessCommand(buf []byte) ([]byte, error) {
	return []byte(""), nil
}

func NewTargetDriver(driver string, tgt *api.SCSITarget) SCSITargetDriver {
	if driver == "iscsi" {
		return iscsit.NewISCSITarget(tgt)
	}
	return nil
}
