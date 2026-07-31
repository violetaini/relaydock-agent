package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestNormalizeMasterURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "canonical host and default port", input: " HTTPS://Example.COM:443/control/ ", want: "https://example.com/control"},
		{name: "IPv6", input: "http://[2001:db8::1]:8080/", want: "http://[2001:db8::1]:8080"},
		{name: "reject credentials", input: "https://user:pass@example.com", wantErr: true},
		{name: "reject query", input: "https://example.com/?token=x", wantErr: true},
		{name: "reject missing host", input: "https:///path", wantErr: true},
		{name: "reject non-http", input: "file:///tmp/socket", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeMasterURL(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("normalizeMasterURL(%q) = %q, want error", test.input, got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("normalizeMasterURL(%q) = %q, %v; want %q", test.input, got, err, test.want)
			}
		})
	}
}

func TestHandleUpdateMasterURLSkipsEquivalentValue(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	original := "master_url: \"https://Example.COM:443/control/\"\ntoken: keep-me\n"
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	handler := NewManageHandler("", "", "")
	handler.SetConfigPath(configPath)
	request := httptest.NewRequest(http.MethodPost, constants.PathChildUpdateMasterURL, strings.NewReader(`{"master_url":"https://example.com/control"}`))
	request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
	response := httptest.NewRecorder()

	handler.HandleUpdateMasterURL(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		Unchanged bool `json:"unchanged"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Unchanged {
		t.Fatalf("response did not report unchanged: %s", response.Body.String())
	}
	current, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != original {
		t.Fatalf("equivalent master URL rewrote config:\n%s", current)
	}
}
