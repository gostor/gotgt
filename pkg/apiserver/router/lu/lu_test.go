package lu

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/scsi"
	"golang.org/x/net/context"
)

func resetService() {
	s := scsi.NewSCSITargetService()
	targets, _ := s.GetTargetList()
	for _, t := range targets {
		s.DeleteTarget(t.Name, true)
	}
}

func TestGetLuListEmpty(t *testing.T) {
	resetService()
	r := &luRouter{}

	req, _ := http.NewRequest("GET", "/lu/list?target=iqn.test", nil)
	req.ParseForm()
	w := httptest.NewRecorder()

	err := r.getLuList(context.Background(), w, req, nil)
	if err != nil {
		t.Fatalf("getLuList failed: %v", err)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var lus []api.LuInfo
	if err := json.Unmarshal(w.Body.Bytes(), &lus); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(lus) != 0 {
		t.Fatalf("expected 0 LUs for non-existent target, got %d", len(lus))
	}
}

func TestGetLuListNoTarget(t *testing.T) {
	r := &luRouter{}

	req, _ := http.NewRequest("GET", "/lu/list", nil)
	w := httptest.NewRecorder()

	err := r.getLuList(context.Background(), w, req, nil)
	if err == nil {
		t.Fatal("expected error when target param is missing")
	}
}

func TestDeleteLu(t *testing.T) {
	resetService()
	r := &luRouter{}

	body, _ := json.Marshal(api.LuRemoveOptions{TargetName: "iqn.test", LUN: 0})
	req, _ := http.NewRequest("DELETE", "/lu/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err := r.deleteLu(context.Background(), w, req, nil)
	if err != nil {
		t.Fatalf("deleteLu failed: %v", err)
	}
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", w.Code)
	}
}

func TestDeleteLuNoTarget(t *testing.T) {
	r := &luRouter{}

	body, _ := json.Marshal(api.LuRemoveOptions{TargetName: "", LUN: 0})
	req, _ := http.NewRequest("DELETE", "/lu/delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	err := r.deleteLu(context.Background(), w, req, nil)
	if err == nil {
		t.Fatal("expected error when target name is empty")
	}
}
