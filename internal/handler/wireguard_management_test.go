package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"
	"github.com/violetaini/relaydock-agent/internal/embedded"
	"github.com/violetaini/relaydock-agent/internal/limiter"
)

func wireGuardManagementTestKey(value string) string {
	return strings.Repeat(value, 32)
}

func wireGuardManagementBase64Key(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func TestWireGuardServerPeerFromClientValidatesAndSanitizes(t *testing.T) {
	publicKey := wireGuardManagementBase64Key(1)
	preSharedKey := wireGuardManagementTestKey("02")
	peer, err := wireGuardServerPeerFromClient(map[string]interface{}{
		"publicKey":    publicKey,
		"email":        "user@example.com",
		"address":      "10.0.0.2/32",
		"endpoint":     "198.51.100.2:51820",
		"allowedIPs":   []interface{}{"10.0.0.2/32", "fd00::2/128"},
		"keepAlive":    float64(25),
		"preSharedKey": preSharedKey,
		"privateKey":   "must-not-leak",
	})
	if err != nil {
		t.Fatalf("wireGuardServerPeerFromClient: %v", err)
	}
	if got, want := peer, map[string]interface{}{
		"publicKey":    publicKey,
		"allowedIPs":   []string{"10.0.0.2/32", "fd00::2/128"},
		"keepAlive":    uint32(25),
		"preSharedKey": preSharedKey,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("peer=%#v want %#v", got, want)
	}
}

func TestWireGuardServerPeerFromClientRejectsInvalidPeerFields(t *testing.T) {
	valid := func() map[string]interface{} {
		return map[string]interface{}{
			"publicKey":  wireGuardManagementTestKey("03"),
			"allowedIPs": []interface{}{"10.0.0.2/32"},
			"keepAlive":  float64(25),
		}
	}
	tests := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{name: "malformed public key", mutate: func(peer map[string]interface{}) { peer["publicKey"] = "short" }},
		{name: "missing allowed IPs", mutate: func(peer map[string]interface{}) { delete(peer, "allowedIPs") }},
		{name: "subnet allowed IP", mutate: func(peer map[string]interface{}) { peer["allowedIPs"] = []interface{}{"10.0.0.0/24"} }},
		{name: "non-string allowed IP", mutate: func(peer map[string]interface{}) { peer["allowedIPs"] = []interface{}{123} }},
		{name: "duplicate allowed IP", mutate: func(peer map[string]interface{}) { peer["allowedIPs"] = []interface{}{"10.0.0.2/32", "10.0.0.2/32"} }},
		{name: "negative keepalive", mutate: func(peer map[string]interface{}) { peer["keepAlive"] = -1 }},
		{name: "fractional keepalive", mutate: func(peer map[string]interface{}) { peer["keepAlive"] = 1.5 }},
		{name: "oversized keepalive", mutate: func(peer map[string]interface{}) { peer["keepAlive"] = 65536 }},
		{name: "string keepalive", mutate: func(peer map[string]interface{}) { peer["keepAlive"] = "25" }},
		{name: "malformed preshared key", mutate: func(peer map[string]interface{}) { peer["preSharedKey"] = "short" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			peer := valid()
			test.mutate(peer)
			if _, err := wireGuardServerPeerFromClient(peer); err == nil {
				t.Fatalf("wireGuardServerPeerFromClient(%#v) succeeded", peer)
			}
		})
	}
}

func TestApplyAddClientToConfigSupportsWireGuardPeers(t *testing.T) {
	publicKey := wireGuardManagementTestKey("04")
	config := map[string]interface{}{
		"inbounds": []interface{}{
			map[string]interface{}{
				"tag":      "wg",
				"protocol": "wireguard",
				"settings": map[string]interface{}{},
			},
		},
	}

	target, changed, err := applyAddClientToConfig(config, "wg", map[string]interface{}{
		"publicKey":  publicKey,
		"email":      "user@example.com",
		"address":    "10.0.0.2/32",
		"endpoint":   "198.51.100.2:51820",
		"allowedIPs": []string{"10.0.0.2/32"},
		"keepAlive":  25,
	})
	if err != nil {
		t.Fatalf("applyAddClientToConfig: %v", err)
	}
	if !changed {
		t.Fatal("expected config change")
	}
	settings := target["settings"].(map[string]interface{})
	peers := settings["peers"].([]interface{})
	if len(peers) != 1 {
		t.Fatalf("peers=%#v", peers)
	}
	peer := peers[0].(map[string]interface{})
	if _, ok := peer["email"]; ok {
		t.Fatalf("wireguard peer leaked email metadata: %#v", peer)
	}
	if _, ok := peer["endpoint"]; ok {
		t.Fatalf("wireguard peer leaked endpoint metadata: %#v", peer)
	}

	_, changed, err = applyAddClientToConfig(config, "wg", map[string]interface{}{
		"publicKey":  publicKey,
		"allowedIPs": []string{"10.0.0.2/32"},
	})
	if err != nil {
		t.Fatalf("second applyAddClientToConfig: %v", err)
	}
	if changed {
		t.Fatal("duplicate wireguard peer should be no-op")
	}
}

func TestWireGuardClientRuntimeFailureRollsBackConfigAndRuntime(t *testing.T) {
	firstKey := wireGuardManagementTestKey("05")
	secondKey := wireGuardManagementTestKey("06")
	tests := []struct {
		name              string
		action            string
		originalPeerKeys  []string
		requestKey        string
		changedPeerCount  int
		rollbackPeerCount int
	}{
		{name: "add", action: "add-client", originalPeerKeys: []string{firstKey}, requestKey: secondKey, changedPeerCount: 2, rollbackPeerCount: 1},
		{name: "remove", action: "remove-client", originalPeerKeys: []string{firstKey, secondKey}, requestKey: secondKey, changedPeerCount: 1, rollbackPeerCount: 2},
		{name: "add no-op", action: "add-client", originalPeerKeys: []string{firstKey, secondKey}, requestKey: secondKey, changedPeerCount: 2, rollbackPeerCount: 2},
		{name: "remove no-op", action: "remove-client", originalPeerKeys: []string{firstKey}, requestKey: secondKey, changedPeerCount: 1, rollbackPeerCount: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			peers := make([]interface{}, 0, len(test.originalPeerKeys))
			for i, publicKey := range test.originalPeerKeys {
				peers = append(peers, map[string]interface{}{
					"publicKey":  publicKey,
					"allowedIPs": []interface{}{[]string{"10.0.0.2/32", "10.0.0.3/32"}[i]},
					"keepAlive":  float64(25),
				})
			}
			config := map[string]interface{}{
				"inbounds": []interface{}{
					map[string]interface{}{
						"tag":      "wg",
						"protocol": "wireguard",
						"settings": map[string]interface{}{"peers": peers},
					},
				},
			}
			original, err := json.MarshalIndent(config, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			tempDir := t.TempDir()
			configPath := filepath.Join(tempDir, "config.json")
			if err := os.WriteFile(configPath, original, 0600); err != nil {
				t.Fatal(err)
			}
			originalPaths := constants.DefaultXrayConfigPaths
			constants.DefaultXrayConfigPaths = []string{configPath}
			t.Cleanup(func() { constants.DefaultXrayConfigPaths = originalPaths })
			limiter.ConfigurePersistentSnapshotPath(filepath.Join(tempDir, "limiter-state.json"))
			t.Cleanup(func() { limiter.ConfigurePersistentSnapshotPath("") })
			if test.action == "add-client" {
				if err := limiter.PersistInboundSnapshot(limiter.PersistentInboundSnapshot{
					InboundTag: "wg",
					Users:      []limiter.UserInfo{{Email: "alice@example.com"}},
					WireGuardPeers: []limiter.WireGuardPeerUser{
						{Address: "10.0.0.3/32", Email: "alice@example.com"},
					},
				}); err != nil {
					t.Fatalf("persist limiter snapshot: %v", err)
				}
			}

			handler := NewManageHandler("", "", "")
			handler.SetXrayMode("embedded")
			var runtimePeerCounts []int
			handler.inboundClientRuntimeReplace = func(_ context.Context, tag string, inbound map[string]interface{}) error {
				if tag != "wg" {
					t.Fatalf("runtime tag=%q", tag)
				}
				settings := inbound["settings"].(map[string]interface{})
				runtimePeerCounts = append(runtimePeerCounts, len(settings["peers"].([]interface{})))
				if len(runtimePeerCounts) == 1 {
					return errors.New("runtime replace failed")
				}
				return nil
			}
			response := httptest.NewRecorder()
			handler.manageInboundClient(response, context.Background(), test.action, &InboundRequest{
				Tag: "wg",
				Client: map[string]interface{}{
					"publicKey":  test.requestKey,
					"allowedIPs": []interface{}{"10.0.0.3/32"},
					"keepAlive":  float64(25),
				},
			})
			if response.Code < http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if got, want := runtimePeerCounts, []int{test.changedPeerCount, test.rollbackPeerCount}; !reflect.DeepEqual(got, want) {
				t.Fatalf("runtime peer counts=%v want %v", got, want)
			}
			current, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(current) != string(original) {
				t.Fatalf("failed runtime apply left mutated config:\n%s", current)
			}
		})
	}
}

func TestWireGuardAddRejectsMissingDurableLimiterMapping(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := []byte(`{
  "inbounds": [
    {
      "tag": "wg",
      "protocol": "wireguard",
      "settings": {
        "peers": []
      }
    }
  ]
}`)
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	originalPaths := constants.DefaultXrayConfigPaths
	constants.DefaultXrayConfigPaths = []string{configPath}
	t.Cleanup(func() { constants.DefaultXrayConfigPaths = originalPaths })

	statePath := filepath.Join(tempDir, "limiter-state.json")
	limiter.ConfigurePersistentSnapshotPath(statePath)
	t.Cleanup(func() { limiter.ConfigurePersistentSnapshotPath("") })
	if err := limiter.PersistInboundSnapshot(limiter.PersistentInboundSnapshot{
		InboundTag: "wg",
		Users:      []limiter.UserInfo{{Email: "probe@relaydock.internal"}},
		WireGuardPeers: []limiter.WireGuardPeerUser{
			{Address: "10.0.0.1/32", Email: "probe@relaydock.internal"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	handler := NewManageHandler("", "", "")
	handler.SetXrayMode("embedded")
	runtimeCalls := 0
	handler.inboundClientRuntimeReplace = func(context.Context, string, map[string]interface{}) error {
		runtimeCalls++
		return nil
	}
	response := httptest.NewRecorder()
	handler.manageInboundClient(response, context.Background(), "add-client", &InboundRequest{
		Tag: "wg",
		Client: map[string]interface{}{
			"publicKey":  wireGuardManagementTestKey("07"),
			"allowedIPs": []interface{}{"10.0.0.3/32"},
			"keepAlive":  float64(25),
		},
	})

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if runtimeCalls != 0 {
		t.Fatalf("runtime calls=%d", runtimeCalls)
	}
	current, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current, config) {
		t.Fatalf("rejected peer mutated config:\n%s", current)
	}
	if _, err := os.Stat(statePath + ".required"); !os.IsNotExist(err) {
		t.Fatalf("rejected peer wrote required marker: %v", err)
	}
}

func TestWireGuardInboundRequiresEveryDurableLimiterMapping(t *testing.T) {
	tempDir := t.TempDir()
	statePath := filepath.Join(tempDir, "limiter-state.json")
	limiter.ConfigurePersistentSnapshotPath(statePath)
	t.Cleanup(func() { limiter.ConfigurePersistentSnapshotPath("") })
	if err := limiter.PersistInboundSnapshot(limiter.PersistentInboundSnapshot{
		InboundTag: "wg",
		Users:      []limiter.UserInfo{{Email: "alice@example.com"}},
		WireGuardPeers: []limiter.WireGuardPeerUser{
			{Address: "10.0.0.2/32", Email: "alice@example.com"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	inbound := map[string]interface{}{
		"tag":      "wg",
		"protocol": "wireguard",
		"settings": map[string]interface{}{
			"peers": []interface{}{map[string]interface{}{
				"publicKey":  wireGuardManagementTestKey("09"),
				"allowedIPs": []interface{}{"10.0.0.2/32"},
			}},
		},
	}
	if err := requireWireGuardInboundPeerMappings(inbound); err != nil {
		t.Fatalf("mapped inbound rejected: %v", err)
	}
	if _, err := os.Stat(statePath + ".required"); err != nil {
		t.Fatalf("required marker missing: %v", err)
	}

	peers := inbound["settings"].(map[string]interface{})["peers"].([]interface{})
	peers[0].(map[string]interface{})["allowedIPs"] = []interface{}{"10.0.0.3/32"}
	if err := requireWireGuardInboundPeerMappings(inbound); err == nil {
		t.Fatal("unmapped full WireGuard inbound was accepted")
	}
}

func TestBatchApplyRejectsWireGuardBeforeAnySideEffects(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := []byte(`{
  "inbounds": [
    {"tag": "vless", "protocol": "vless", "settings": {"clients": []}},
    {"tag": "wg", "protocol": "wireguard", "settings": {"peers": []}}
  ],
  "routing": {
    "rules": [
      {"type": "field", "marktag": "managed-route", "user": ["admin"], "outboundTag": "direct"}
    ]
  }
}`)
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	originalPaths := constants.DefaultXrayConfigPaths
	constants.DefaultXrayConfigPaths = []string{configPath}
	t.Cleanup(func() { constants.DefaultXrayConfigPaths = originalPaths })

	statePath := filepath.Join(tempDir, "limiter-state.json")
	limiter.ConfigurePersistentSnapshotPath(statePath)
	t.Cleanup(func() { limiter.ConfigurePersistentSnapshotPath("") })
	if err := limiter.PersistInboundSnapshot(limiter.PersistentInboundSnapshot{
		InboundTag: "wg",
		Users:      []limiter.UserInfo{{Email: "alice@example.com"}},
		WireGuardPeers: []limiter.WireGuardPeerUser{
			{Address: "10.0.0.2/32", Email: "alice@example.com"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}

	body, err := json.Marshal(BatchApplyRequest{
		InboundClients: []BatchInboundClient{
			{Tag: "vless", Client: map[string]interface{}{"id": "client-a", "email": "alice@example.com"}},
			{Tag: "wg", Client: map[string]interface{}{
				"publicKey":  wireGuardManagementTestKey("08"),
				"allowedIPs": []interface{}{"10.0.0.2/32"},
				"keepAlive":  float64(25),
			}},
		},
		RoutingUserAdditions: []BatchRoutingAddition{
			{Marktag: "managed-route", UserEmail: "alice@example.com"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewManageHandler("test-token", "", "")
	handler.SetXrayMode("embedded")
	request := httptest.NewRequest(http.MethodPost, constants.PathChildBatchApply, bytes.NewReader(body))
	request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
	request.Header.Set(constants.HeaderAuthorization, constants.BearerPrefix+"test-token")
	response := httptest.NewRecorder()

	handler.HandleBatchApply(response, request)

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "WireGuard client mutations are not supported by batch apply") {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
	currentConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentConfig, config) {
		t.Fatalf("rejected batch mutated config:\n%s", currentConfig)
	}
	currentState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentState, stateBefore) {
		t.Fatalf("rejected batch mutated limiter state:\n%s", currentState)
	}
	if _, err := os.Stat(statePath + ".required"); !os.IsNotExist(err) {
		t.Fatalf("rejected batch wrote required marker: %v", err)
	}
}

func TestWireGuardInboundRemovalClearsLimiterStateBeforeTagReuse(t *testing.T) {
	portReservation, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portReservation.LocalAddr().(*net.UDPAddr).Port
	if err := portReservation.Close(); err != nil {
		t.Fatal(err)
	}

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := []byte(fmt.Sprintf(`{
  "inbounds": [
    {
      "tag": "shared-tag",
      "listen": "127.0.0.1",
      "port": %d,
      "protocol": "wireguard",
      "settings": {
        "secretKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "address": ["10.66.0.1/32"],
        "mtu": 1420,
        "peers": [
          {
            "publicKey": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            "allowedIPs": ["10.66.0.2/32"],
            "keepAlive": 25
          }
        ]
      }
    }
  ],
  "outbounds": [{"tag": "direct", "protocol": "freedom"}]
}`, port))
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	originalPaths := constants.DefaultXrayConfigPaths
	constants.DefaultXrayConfigPaths = []string{configPath}
	t.Cleanup(func() { constants.DefaultXrayConfigPaths = originalPaths })

	statePath := filepath.Join(tempDir, "limiter-state.json")
	limiter.ConfigurePersistentSnapshotPath(statePath)
	t.Cleanup(func() { limiter.ConfigurePersistentSnapshotPath("") })
	snapshot := limiter.PersistentInboundSnapshot{
		InboundTag: "shared-tag",
		Users:      []limiter.UserInfo{{Email: "alice@example.com"}},
		WireGuardPeers: []limiter.WireGuardPeerUser{
			{Address: "10.66.0.2/32", Email: "alice@example.com"},
		},
	}
	if err := limiter.PersistInboundSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := limiter.RequireWireGuardPeerMappings(snapshot.InboundTag, []string{"10.66.0.2/32"}); err != nil {
		t.Fatal(err)
	}

	xray := embedded.New(configPath)
	if err := xray.Start(); err != nil {
		t.Fatalf("start embedded Xray: %v", err)
	}
	t.Cleanup(func() {
		if err := xray.Stop(); err != nil {
			t.Errorf("stop embedded Xray: %v", err)
		}
	})
	if !xray.GetLimiter().HasWireGuardPeerMappings("shared-tag") {
		t.Fatal("WireGuard identity requirement was not restored")
	}

	handler := NewManageHandler("", "", "")
	handler.SetXrayMode("embedded")
	handler.SetEmbeddedXray(xray)
	handler.inboundFirewallSync = func(context.Context) error { return nil }
	removeRequest := httptest.NewRequest(http.MethodPost, constants.PathChildInbounds, strings.NewReader(`{"action":"remove","tag":"shared-tag"}`))
	removeResponse := httptest.NewRecorder()
	handler.manageInbound(removeResponse, removeRequest)
	if removeResponse.Code != http.StatusOK {
		t.Fatalf("remove status=%d body=%s", removeResponse.Code, removeResponse.Body.String())
	}
	if xray.GetLimiter().HasWireGuardPeerMappings("shared-tag") {
		t.Fatal("WireGuard identity requirement survived inbound removal")
	}
	snapshots, err := limiter.LoadPersistentInboundSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 0 {
		t.Fatalf("removed inbound snapshot survived: %#v", snapshots)
	}
	if _, err := os.Stat(statePath + ".required"); !os.IsNotExist(err) {
		t.Fatalf("required marker survived removed WireGuard inbound: %v", err)
	}

	addBody, err := json.Marshal(InboundRequest{
		Action: "add",
		Inbound: map[string]interface{}{
			"tag":      "shared-tag",
			"listen":   "127.0.0.1",
			"port":     port,
			"protocol": "vless",
			"settings": map[string]interface{}{
				"decryption": "none",
				"clients": []interface{}{map[string]interface{}{
					"id":    "11111111-1111-4111-8111-111111111111",
					"email": "alice@example.com",
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	addRequest := httptest.NewRequest(http.MethodPost, constants.PathChildInbounds, bytes.NewReader(addBody))
	addResponse := httptest.NewRecorder()
	handler.manageInbound(addResponse, addRequest)
	if addResponse.Code != http.StatusOK {
		t.Fatalf("add VLESS status=%d body=%s", addResponse.Code, addResponse.Body.String())
	}
	if xray.GetLimiter().HasWireGuardPeerMappings("shared-tag") {
		t.Fatal("VLESS tag reuse inherited the removed WireGuard identity requirement")
	}
	found := false
	for _, tag := range xray.ListInbounds() {
		if tag == "shared-tag" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("VLESS inbound was not added with the reused tag")
	}
}
