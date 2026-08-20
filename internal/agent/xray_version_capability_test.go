package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/violetaini/relaydock-agent/internal/config"
	"github.com/violetaini/relaydock-agent/internal/constants"
	"github.com/violetaini/relaydock-agent/internal/limiter"
)

func TestAdvertisedCapabilitiesIncludeXrayVersionSelection(t *testing.T) {
	for _, embedded := range []bool{false, true} {
		for _, rpcAvailable := range []bool{false, true} {
			capabilities := advertisedCapabilities(rpcAvailable, false, embedded)
			if !capabilities[constants.CapabilityXrayVersionSelectV1] {
				t.Fatalf("rpcAvailable=%v capabilities=%v", rpcAvailable, capabilities)
			}
			if !capabilities[constants.CapabilityXrayAuthorizationV2] {
				t.Fatalf("runtime authorization capability missing: %v", capabilities)
			}
			if got := capabilities[constants.CapabilityWireGuardPeerUsersV1]; got != embedded {
				t.Fatalf("embedded=%v wireguard capability=%v capabilities=%v", embedded, got, capabilities)
			}
			if !capabilities[constants.CapabilityLimiterDeniedV1] {
				t.Fatalf("explicit limiter deny capability missing: %v", capabilities)
			}
			if got := capabilities[constants.CapabilityForwardingSpeedLimitV1]; got != embedded {
				t.Fatalf("embedded=%v forwarding speed capability=%v capabilities=%v", embedded, got, capabilities)
			}
		}
	}
}

func TestHTTPTrafficAdvertisesXrayAuthorizationV2(t *testing.T) {
	for _, test := range []struct {
		mode          string
		wantWireGuard bool
	}{
		{mode: "embedded", wantWireGuard: true},
		{mode: "external", wantWireGuard: false},
	} {
		t.Run(test.mode, func(t *testing.T) {
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

			client := NewClient(&config.Config{MasterURL: server.URL, Token: "test-token", XrayMode: test.mode})
			client.httpClient = server.Client()
			if err := client.sendTrafficHTTP(context.Background()); err != nil {
				t.Fatalf("send HTTP traffic: %v", err)
			}
			got := <-capabilities
			if !got[constants.CapabilityXrayAuthorizationV2] {
				t.Fatalf("traffic capabilities=%v", got)
			}
			if actual := got[constants.CapabilityWireGuardPeerUsersV1]; actual != test.wantWireGuard {
				t.Fatalf("wireguard capability=%v want %v; capabilities=%v", actual, test.wantWireGuard, got)
			}
			if !got[constants.CapabilityLimiterDeniedV1] {
				t.Fatalf("explicit limiter deny capability missing: %v", got)
			}
			if actual := got[constants.CapabilityForwardingSpeedLimitV1]; actual != test.wantWireGuard {
				t.Fatalf("forwarding speed capability=%v want %v; capabilities=%v", actual, test.wantWireGuard, got)
			}
		})
	}
}

func TestHTTPHeartbeatAdvertisesLimiterDeniedV1(t *testing.T) {
	capabilities := make(chan map[string]bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != constants.PathRemoteHeartbeat {
			t.Errorf("path=%s want %s", r.URL.Path, constants.PathRemoteHeartbeat)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var payload struct {
			Capabilities map[string]bool `json:"capabilities"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode heartbeat payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		capabilities <- payload.Capabilities
		w.Header().Set(constants.HeaderContentType, constants.ContentTypeJSON)
		_, _ = w.Write([]byte(`{"server_time":1}`))
	}))
	defer server.Close()

	client := NewClient(&config.Config{MasterURL: server.URL, Token: "test-token", XrayMode: "embedded"})
	client.httpClient = server.Client()
	if err := client.sendHeartbeatHTTP(context.Background()); err != nil {
		t.Fatalf("send HTTP heartbeat: %v", err)
	}
	got := <-capabilities
	if !got[constants.CapabilityLimiterDeniedV1] {
		t.Fatalf("heartbeat capabilities=%v", got)
	}
	if !got[constants.CapabilityForwardingSpeedLimitV1] {
		t.Fatalf("heartbeat forwarding speed capability missing: %v", got)
	}
}

func TestWSHeartbeatAdvertisesLimiterDeniedV1(t *testing.T) {
	type heartbeatResult struct {
		messageType  string
		capabilities map[string]bool
		err          error
	}
	result := make(chan heartbeatResult, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			result <- heartbeatResult{err: err}
			return
		}
		defer conn.Close()
		_, body, err := conn.ReadMessage()
		if err != nil {
			result <- heartbeatResult{err: err}
			return
		}
		var message struct {
			Type    string          `json:"type"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(body, &message); err != nil {
			result <- heartbeatResult{err: err}
			return
		}
		var payload struct {
			Capabilities map[string]bool `json:"capabilities"`
		}
		if err := json.Unmarshal(message.Payload, &payload); err != nil {
			result <- heartbeatResult{err: err}
			return
		}
		result <- heartbeatResult{messageType: message.Type, capabilities: payload.Capabilities}
	}))
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial heartbeat test WebSocket: %v", err)
	}
	defer conn.Close()
	client := NewClient(&config.Config{ListenPort: "50100", XrayMode: "embedded"})
	if err := client.sendHeartbeat(conn); err != nil {
		t.Fatalf("send WS heartbeat: %v", err)
	}
	got := <-result
	if got.err != nil {
		t.Fatalf("read WS heartbeat: %v", got.err)
	}
	if got.messageType != "heartbeat" {
		t.Fatalf("message type=%q want heartbeat", got.messageType)
	}
	if !got.capabilities[constants.CapabilityLimiterDeniedV1] {
		t.Fatalf("heartbeat capabilities=%v", got.capabilities)
	}
	if !got.capabilities[constants.CapabilityForwardingSpeedLimitV1] {
		t.Fatalf("WS heartbeat forwarding speed capability missing: %v", got.capabilities)
	}
}

func TestWSLimiterConfigPayloadDecodesInboundSharedLimit(t *testing.T) {
	var payload WSLimiterConfigPayload
	if err := json.Unmarshal([]byte(`{
		"inbound_tag":"forward-42-hop-0",
		"node_limit":1250000,
		"inbound_shared_limit":true,
		"users":[]
	}`), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.InboundTag != "forward-42-hop-0" || payload.NodeLimit != 1250000 || !payload.InboundSharedLimit {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestWSLimiterConfigPersistsInboundSharedLimit(t *testing.T) {
	limiter.ConfigurePersistentSnapshotPath(filepath.Join(t.TempDir(), "limiter-state.json"))
	t.Cleanup(func() { limiter.ConfigurePersistentSnapshotPath("") })

	client := NewClient(&config.Config{XrayMode: "embedded"})
	client.licenseStatus = &LicenseStatus{Plan: &LicensePlanInfo{Features: []string{"limiter"}}}
	client.handleLimiterConfig(WSLimiterConfigPayload{
		InboundTag:         "forward-42-hop-0",
		NodeLimit:          1250000,
		InboundSharedLimit: true,
	})

	snapshots, err := limiter.LoadPersistentInboundSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 || snapshots[0].InboundTag != "forward-42-hop-0" ||
		snapshots[0].NodeLimit != 1250000 || !snapshots[0].InboundSharedLimit {
		t.Fatalf("snapshots=%+v", snapshots)
	}
}
