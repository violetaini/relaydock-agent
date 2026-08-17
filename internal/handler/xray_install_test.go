package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestDecodeXrayInstallRequest(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
		wantErr bool
	}{
		{name: "empty body keeps latest compatibility", body: "", want: ""},
		{name: "empty object keeps latest compatibility", body: `{}`, want: ""},
		{name: "empty version keeps latest compatibility", body: `{"version":""}`, want: ""},
		{name: "normalizes missing prefix", body: `{"version":"26.7.28"}`, want: "v26.7.28"},
		{name: "keeps version prefix", body: `{"version":"v26.7.28"}`, want: "v26.7.28"},
		{name: "trims version", body: `{"version":"  v26.7.28  "}`, want: "v26.7.28"},
		{name: "rejects prerelease suffix", body: `{"version":"v26.7.28-rc1"}`, wantErr: true},
		{name: "rejects uppercase prefix", body: `{"version":"V26.7.28"}`, wantErr: true},
		{name: "rejects incomplete version", body: `{"version":"v26.7"}`, wantErr: true},
		{name: "rejects unknown field", body: `{"version":"v26.7.28","force":true}`, wantErr: true},
		{name: "rejects trailing JSON", body: `{"version":"v26.7.28"}{}`, wantErr: true},
		{name: "rejects null", body: `null`, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := decodeXrayInstallRequest(strings.NewReader(test.body))
			if test.wantErr {
				if err == nil {
					t.Fatalf("decodeXrayInstallRequest(%q)=%q, want error", test.body, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeXrayInstallRequest(%q): %v", test.body, err)
			}
			if got != test.want {
				t.Fatalf("decodeXrayInstallRequest(%q)=%q, want %q", test.body, got, test.want)
			}
		})
	}
}

func TestNewXrayInstallCommandUsesValidatedVersionEnvironment(t *testing.T) {
	const targetVersion = "v26.7.28"
	t.Setenv("XRAY_TARGET_VERSION", "v0.0.0")
	cmd := newXrayInstallCommand(context.Background(), targetVersion)

	if len(cmd.Args) != 3 || cmd.Args[0] != "bash" || cmd.Args[1] != "-c" {
		t.Fatalf("unexpected command arguments: %v", cmd.Args)
	}
	if strings.Contains(cmd.Args[2], targetVersion) {
		t.Fatalf("target version was interpolated into shell script: %q", cmd.Args[2])
	}
	if !strings.Contains(cmd.Args[2], `install --version "$XRAY_TARGET_VERSION" --force`) {
		t.Fatalf("versioned install arguments missing from script: %q", cmd.Args[2])
	}
	if !strings.Contains(cmd.Args[2], `bash "$installer_path" install`) {
		t.Fatalf("latest-compatible install branch missing from script: %q", cmd.Args[2])
	}

	wantEnv := "XRAY_TARGET_VERSION=" + targetVersion
	found := 0
	for _, value := range cmd.Env {
		if strings.HasPrefix(value, "XRAY_TARGET_VERSION=") {
			found++
			if value != wantEnv {
				t.Fatalf("unexpected Xray version environment: %q", value)
			}
		}
	}
	if found != 1 {
		t.Fatalf("command environment contains %d Xray version entries, want exactly one", found)
	}
}

func TestXrayInstallHandlersRejectInvalidVersionBeforeExecution(t *testing.T) {
	handler := NewManageHandler("", "", "")
	for name, handle := range map[string]http.HandlerFunc{
		"non-stream": handler.HandleXrayInstall,
		"stream":     handler.HandleXrayInstallStream,
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, constants.PathChildXrayInstall, strings.NewReader(`{"version":"latest"}`))
			request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
			response := httptest.NewRecorder()

			handle(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestSSEStreamCommandFailureDoesNotEmitCompletion(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, constants.PathChildXrayInstallStream, nil)
	response := httptest.NewRecorder()

	err := sseStreamCmd(response, request, exec.Command("bash", "-c", "exit 7"), "must not complete")

	if err == nil {
		t.Fatal("failed command returned nil")
	}
	body := response.Body.String()
	if !strings.Contains(body, `"type":"error"`) || strings.Contains(body, `"type":"complete"`) {
		t.Fatalf("unexpected SSE body: %s", body)
	}
}

func TestSystemInfoAdvertisesXrayVersionSelection(t *testing.T) {
	for _, test := range []struct {
		mode          string
		wantWireGuard bool
	}{
		{mode: "embedded", wantWireGuard: true},
		{mode: "external", wantWireGuard: false},
	} {
		t.Run(test.mode, func(t *testing.T) {
			handler := NewManageHandler("", "", "")
			handler.SetXrayMode(test.mode)
			request := httptest.NewRequest(http.MethodGet, constants.PathChildSystemInfo, nil)
			request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
			response := httptest.NewRecorder()

			handler.HandleSystemInfo(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var payload struct {
				Capabilities map[string]bool `json:"capabilities"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if !payload.Capabilities[constants.CapabilityXrayVersionSelectV1] {
				t.Fatalf("capabilities=%v", payload.Capabilities)
			}
			if !payload.Capabilities[constants.CapabilityXrayAuthorizationV2] {
				t.Fatalf("runtime authorization capability missing: %v", payload.Capabilities)
			}
			if actual := payload.Capabilities[constants.CapabilityWireGuardPeerUsersV1]; actual != test.wantWireGuard {
				t.Fatalf("wireguard capability=%v want %v; capabilities=%v", actual, test.wantWireGuard, payload.Capabilities)
			}
			if !payload.Capabilities[constants.CapabilityLimiterDeniedV1] {
				t.Fatalf("explicit limiter deny capability missing: %v", payload.Capabilities)
			}
		})
	}
}
