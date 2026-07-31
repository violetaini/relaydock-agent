package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestSwitchToExternalRequiresExplicitInstallationBeforeConfigWrite(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	original := "master_url: https://example.com\nxray_mode: embedded\n"
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	handler := NewManageHandler("", "", "")
	handler.SetConfigPath(configPath)
	handler.externalXrayLookPath = func(string) (string, error) {
		return "", errors.New("not found")
	}
	request := httptest.NewRequest(http.MethodPost, constants.PathChildSwitchXrayMode, strings.NewReader(`{"xray_mode":"external"}`))
	request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
	response := httptest.NewRecorder()

	handler.HandleSwitchXrayMode(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	current, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != original {
		t.Fatalf("failed external preflight changed config:\n%s", current)
	}
}
