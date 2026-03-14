package scsi

import (
	"testing"

	"github.com/google/uuid"
	"github.com/gostor/gotgt/pkg/api"
)

// nullBackingStore is a minimal backing store for tests.
type nullBackingStore struct {
	BaseBackingStore
}

func (bs *nullBackingStore) Open(dev *api.SCSILu, path string) error              { return nil }
func (bs *nullBackingStore) Close(dev *api.SCSILu) error                          { return nil }
func (bs *nullBackingStore) Init(dev *api.SCSILu, Opts string) error              { return nil }
func (bs *nullBackingStore) Exit(dev *api.SCSILu) error                           { return nil }
func (bs *nullBackingStore) Size(dev *api.SCSILu) uint64                          { return 0 }
func (bs *nullBackingStore) Read(offset, tl int64) ([]byte, error)                { return nil, nil }
func (bs *nullBackingStore) Write(wbuf []byte, offset int64) error                { return nil }
func (bs *nullBackingStore) DataSync(offset, tl int64) error                      { return nil }
func (bs *nullBackingStore) DataAdvise(offset, length int64, advise uint32) error { return nil }
func (bs *nullBackingStore) Unmap([]api.UnmapBlockDescriptor) error               { return nil }

func init() {
	if _, err := NewBackingStore("null"); err != nil {
		RegisterBackingStore("null", func() (api.BackingStore, error) {
			return &nullBackingStore{
				BaseBackingStore: BaseBackingStore{Name: "null"},
			}, nil
		})
	}
}

func resetTargetService() *SCSITargetService {
	s := NewSCSITargetService()
	s.mutex.Lock()
	s.Targets = []*api.SCSITarget{}
	s.mutex.Unlock()
	return s
}

func TestNewSCSITarget(t *testing.T) {
	s := resetTargetService()

	target, err := s.NewSCSITarget(0, "iscsi", "iqn.2016-09.com.gotgt:test_target")
	if err != nil {
		t.Fatalf("NewSCSITarget failed: %v", err)
	}
	if target == nil {
		t.Fatal("NewSCSITarget returned nil")
	}
	if target.Name != "iqn.2016-09.com.gotgt:test_target" {
		t.Fatalf("expected target name iqn.2016-09.com.gotgt:test_target, got %s", target.Name)
	}
	if target.TID != 0 {
		t.Fatalf("expected TID 0, got %d", target.TID)
	}
	if len(s.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(s.Targets))
	}
	if len(target.TargetPortGroups) != 1 {
		t.Fatalf("expected 1 target port group, got %d", len(target.TargetPortGroups))
	}
}

func TestDeleteTargetSuccess(t *testing.T) {
	s := resetTargetService()

	_, err := s.NewSCSITarget(0, "iscsi", "iqn.2016-09.com.gotgt:delete_me")
	if err != nil {
		t.Fatalf("NewSCSITarget failed: %v", err)
	}

	err = s.DeleteTarget("iqn.2016-09.com.gotgt:delete_me", false)
	if err != nil {
		t.Fatalf("DeleteTarget failed: %v", err)
	}
	if len(s.Targets) != 0 {
		t.Fatalf("expected 0 targets after deletion, got %d", len(s.Targets))
	}
}

func TestDeleteTargetNotFound(t *testing.T) {
	s := resetTargetService()

	err := s.DeleteTarget("iqn.2016-09.com.gotgt:nonexistent", false)
	if err == nil {
		t.Fatal("expected error deleting nonexistent target")
	}
}

func TestDeleteTargetActiveSessions(t *testing.T) {
	s := resetTargetService()

	target, err := s.NewSCSITarget(0, "iscsi", "iqn.2016-09.com.gotgt:busy_target")
	if err != nil {
		t.Fatalf("NewSCSITarget failed: %v", err)
	}

	// Simulate active session
	target.ITNexusMutex.Lock()
	target.ITNexus[uuid.New()] = &api.ITNexus{ID: uuid.New()}
	target.ITNexusMutex.Unlock()

	// Should fail without force
	err = s.DeleteTarget("iqn.2016-09.com.gotgt:busy_target", false)
	if err == nil {
		t.Fatal("expected error deleting target with active sessions")
	}

	// Should succeed with force
	err = s.DeleteTarget("iqn.2016-09.com.gotgt:busy_target", true)
	if err != nil {
		t.Fatalf("DeleteTarget with force failed: %v", err)
	}
	if len(s.Targets) != 0 {
		t.Fatalf("expected 0 targets after forced deletion, got %d", len(s.Targets))
	}
}

func TestDeleteTargetMultiple(t *testing.T) {
	s := resetTargetService()

	s.NewSCSITarget(0, "iscsi", "iqn.2016-09.com.gotgt:target_a")
	s.NewSCSITarget(1, "iscsi", "iqn.2016-09.com.gotgt:target_b")
	s.NewSCSITarget(2, "iscsi", "iqn.2016-09.com.gotgt:target_c")

	if len(s.Targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(s.Targets))
	}

	// Delete middle one
	err := s.DeleteTarget("iqn.2016-09.com.gotgt:target_b", false)
	if err != nil {
		t.Fatalf("DeleteTarget failed: %v", err)
	}
	if len(s.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(s.Targets))
	}
	if s.Targets[0].Name != "iqn.2016-09.com.gotgt:target_a" {
		t.Fatalf("expected target_a first, got %s", s.Targets[0].Name)
	}
	if s.Targets[1].Name != "iqn.2016-09.com.gotgt:target_c" {
		t.Fatalf("expected target_c second, got %s", s.Targets[1].Name)
	}
}
