package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestHandleScanDoesNotModifyConfigOrRestartXray(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "xray.json")
	original := []byte(`{"inbounds": []}`)
	if err := os.WriteFile(configPath, original, 0o644); err != nil {
		t.Fatal(err)
	}

	originalPaths := constants.DefaultXrayConfigPaths
	constants.DefaultXrayConfigPaths = []string{configPath}
	t.Cleanup(func() { constants.DefaultXrayConfigPaths = originalPaths })

	handler := NewManageHandler("", "custom", "exit 99")
	handler.SetXrayMode("embedded")
	request := httptest.NewRequest(http.MethodPost, constants.PathChildScan, nil)
	request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
	response := httptest.NewRecorder()

	handler.HandleScan(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, original) {
		t.Fatalf("scan modified config:\n got %s\nwant %s", content, original)
	}
	var result ScanResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode scan response: %v", err)
	}
	if result.ConfigModified || len(result.ConfigAddedSections) != 0 {
		t.Fatalf("scan reported a config repair: %#v", result)
	}
}
