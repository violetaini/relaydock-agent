package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mmw-agent/internal/constants"
)

func TestHandleSwitchNginxModePersistsBeforeAcknowledging(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("listen_port: 23889\nnginx_mode: managed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h := NewManageHandler("token", "", "")
	h.SetConfigPath(configPath)

	request := httptest.NewRequest(http.MethodPost, constants.PathChildSwitchNginxMode, strings.NewReader(`{"nginx_mode":"reuse_existing"}`))
	request.Header.Set("X-WS-RPC", "1")
	request.RemoteAddr = "ws-rpc"
	response := httptest.NewRecorder()
	h.HandleSwitchNginxMode(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "nginx_mode: reuse_existing") {
		t.Fatalf("mode was not persisted: %s", data)
	}
	if got := h.currentNginxMode(); got != constants.NginxModeReuseExisting {
		t.Fatalf("runtime mode = %q", got)
	}
}

func TestHandleSwitchNginxModeRejectsInvalidMode(t *testing.T) {
	h := NewManageHandler("token", "", "")
	request := httptest.NewRequest(http.MethodPost, constants.PathChildSwitchNginxMode, strings.NewReader(`{"nginx_mode":"invalid"}`))
	request.Header.Set("X-WS-RPC", "1")
	request.RemoteAddr = "ws-rpc"
	response := httptest.NewRecorder()
	h.HandleSwitchNginxMode(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
}

func TestHandleSwitchNginxModeDoesNotChangeRuntimeWhenPersistenceFails(t *testing.T) {
	h := NewManageHandler("token", "", "")
	h.SetConfigPath(filepath.Join(t.TempDir(), "missing", "config.yaml"))

	request := httptest.NewRequest(http.MethodPost, constants.PathChildSwitchNginxMode, strings.NewReader(`{"nginx_mode":"reuse_existing"}`))
	request.Header.Set("X-WS-RPC", "1")
	request.RemoteAddr = "ws-rpc"
	response := httptest.NewRecorder()
	h.HandleSwitchNginxMode(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d; body=%s", response.Code, response.Body.String())
	}
	if got := h.currentNginxMode(); got != constants.NginxModeManaged {
		t.Fatalf("runtime mode changed after persistence failure: %q", got)
	}
}
