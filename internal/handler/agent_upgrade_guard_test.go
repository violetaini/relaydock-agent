package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestResolveAgentUpgradeReleaseRejectsNonNewerTarget(t *testing.T) {
	tests := []struct {
		name    string
		tagName string
		current string
		want    string
		wantErr string
	}{
		{name: "older latest", tagName: "v0.4.1", current: "0.4.3", wantErr: "target is not newer"},
		{name: "equal latest", tagName: "v0.4.3", current: "0.4.3", wantErr: "target is not newer"},
		{name: "newer latest", tagName: "v0.4.4", current: "0.4.3", want: "v0.4.4"},
		{name: "malformed release tag", tagName: "v0.4.4-rc1", current: "0.4.3", wantErr: "invalid release tag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept") != "application/vnd.github+json" {
					t.Fatalf("Accept = %q", r.Header.Get("Accept"))
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"tag_name":"` + tt.tagName + `"}`))
			}))
			defer server.Close()

			got, err := resolveAgentUpgradeRelease(context.Background(), server.Client(), server.URL, tt.current)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveAgentUpgradeRelease error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("release tag = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveAgentUpgradeReleaseFailsClosedOnMetadataFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary failure", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := resolveAgentUpgradeRelease(context.Background(), server.Client(), server.URL, "0.4.3")
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("resolveAgentUpgradeRelease error = %v, want metadata failure", err)
	}
}

func TestHandleAgentUpgradeStreamRejectsBeforeReplacement(t *testing.T) {
	manage := NewManageHandler("test-token", "", "")
	resolverCalled := false
	manage.agentUpgradeReleaseResolver = func(context.Context, string) (string, error) {
		resolverCalled = true
		return "", errors.New("target is not newer")
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, constants.PathChildAgentUpgradeStream, nil)
	request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
	request.Header.Set(constants.HeaderAuthorization, constants.BearerPrefix+"test-token")
	manage.HandleAgentUpgradeStream(recorder, request)

	if !resolverCalled {
		t.Fatal("release resolver was not called")
	}
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "target is not newer") {
		t.Fatalf("response does not explain refusal: %s", recorder.Body.String())
	}
}
