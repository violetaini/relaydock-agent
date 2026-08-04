package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/config"
	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestAdvertisedCapabilitiesIncludeXrayVersionSelection(t *testing.T) {
	for _, rpcAvailable := range []bool{false, true} {
		capabilities := advertisedCapabilities(rpcAvailable, false)
		if !capabilities[constants.CapabilityXrayVersionSelectV1] {
			t.Fatalf("rpcAvailable=%v capabilities=%v", rpcAvailable, capabilities)
		}
		if !capabilities[constants.CapabilityXrayAuthorizationV2] {
			t.Fatalf("runtime authorization capability missing: %v", capabilities)
		}
	}
}

func TestHTTPTrafficAdvertisesXrayAuthorizationV2(t *testing.T) {
	capabilities := make(chan map[string]bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != constants.PathRemoteTraffic {
			t.Errorf("path=%s want %s", r.URL.Path, constants.PathRemoteTraffic)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var payload struct {
			Capabilities map[string]bool `json:"capabilities"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode traffic payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		capabilities <- payload.Capabilities
		w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewClient(&config.Config{MasterURL: server.URL, Token: "test-token"})
	client.httpClient = server.Client()
	if err := client.sendTrafficHTTP(context.Background()); err != nil {
		t.Fatalf("send HTTP traffic: %v", err)
	}
	if got := <-capabilities; !got[constants.CapabilityXrayAuthorizationV2] {
		t.Fatalf("traffic capabilities=%v", got)
	}
}
