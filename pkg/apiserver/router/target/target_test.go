package target

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/scsi"
	_ "github.com/gostor/gotgt/pkg/scsi/backingstore"
	"golang.org/x/net/context"
)

func resetService() *scsi.SCSITargetService {
	s := scsi.NewSCSITargetService()
	// Clear targets for test isolation
	targets, _ := s.GetTargetList()
	for _, t := range targets {
		s.DeleteTarget(t.Name, true)
	}
	return s
}

func TestPostTargetCreate(t *testing.T) {
	resetService()
	r := &targetRouter{}

	body, _ := json.Marshal(api.TargetCreateRequest{Name: "iqn.2016-09.com.gotgt:test"})
	req, _ := http.NewRequest("POST", "/target/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err := r.postTargetCreate(context.Background(), w, req, nil)
	if err != nil {
		t.Fatalf("postTargetCreate failed: %v", err)
	}
	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", w.Code)
	}

	var target api.SCSITarget
	if err := json.Unmarshal(w.Body.Bytes(), &target); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if target.Name != "iqn.2016-09.com.gotgt:test" {
		t.Fatalf("expected target name iqn.2016-09.com.gotgt:test, got %s", target.Name)
	}
}

func TestPostTargetCreateEmptyName(t *testing.T) {
	resetService()
	r := &targetRouter{}

	body, _ := json.Marshal(api.TargetCreateRequest{Name: ""})
	req, _ := http.NewRequest("POST", "/target/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err := r.postTargetCreate(context.Background(), w, req, nil)
	if err == nil {
		t.Fatal("expected error for empty target name")
	}
}

func TestDeleteTarget(t *testing.T) {
	s := resetService()
	r := &targetRouter{}

	s.NewSCSITarget(0, "iscsi", "iqn.2016-09.com.gotgt:to_delete")

	req, _ := http.NewRequest("DELETE", "/target/iqn.2016-09.com.gotgt:to_delete", nil)
	w := httptest.NewRecorder()

	vars := map[string]string{"name": "iqn.2016-09.com.gotgt:to_delete"}
	err := r.deleteTarget(context.Background(), w, req, vars)
	if err != nil {
		t.Fatalf("deleteTarget failed: %v", err)
	}
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
}

func TestDeleteTargetNotFound(t *testing.T) {
	resetService()
	r := &targetRouter{}

	req, _ := http.NewRequest("DELETE", "/target/nonexistent", nil)
	w := httptest.NewRecorder()

	vars := map[string]string{"name": "nonexistent"}
	err := r.deleteTarget(context.Background(), w, req, vars)
	if err == nil {
		t.Fatal("expected error deleting nonexistent target")
	}
}

func TestGetTargetList(t *testing.T) {
	s := resetService()
	r := &targetRouter{}

	s.NewSCSITarget(0, "iscsi", "iqn.2016-09.com.gotgt:list_test")

	req, _ := http.NewRequest("GET", "/target/list", nil)
	w := httptest.NewRecorder()

	err := r.getTargetList(context.Background(), w, req, nil)
	if err != nil {
		t.Fatalf("getTargetList failed: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var targets []*api.SCSITarget
	if err := json.Unmarshal(w.Body.Bytes(), &targets); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(targets) == 0 {
		t.Fatal("expected at least one target")
	}
}
