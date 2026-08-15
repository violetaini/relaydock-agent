package embedded

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	feature_inbound "github.com/xtls/xray-core/features/inbound"

	"github.com/violetaini/relaydock-agent/internal/limiter"
)

func TestValidateConfigProtocolsRejectsDisabledProtocol(t *testing.T) {
	tests := []string{
		`{"inbounds":[{"protocol":"snell"}]}`,
		`{"outbounds":[{"protocol":" SnElL "}]}`,
		`{"protocol":"snell","settings":{}}`,
	}
	for _, raw := range tests {
		if err := ValidateConfigProtocols([]byte(raw)); err == nil || !strings.Contains(err.Error(), "disabled") {
			t.Fatalf("ValidateConfigProtocols(%s) error = %v, want disabled protocol error", raw, err)
		}
	}
}

func TestValidateConfigProtocolsAllowsOtherProtocolFields(t *testing.T) {
	raw := []byte(`{"inbounds":[{"protocol":"vless"}],"routing":{"rules":[{"protocol":["bittorrent"]}]}}`)
	if err := ValidateConfigProtocols(raw); err != nil {
		t.Fatalf("ValidateConfigProtocols rejected an unrelated protocol field: %v", err)
	}
}

func TestSuppressConfiguredInboundsRemovesOnlySelectedTags(t *testing.T) {
	original := []byte(`{
  "inbounds": [
    {"tag": "managed", "protocol": "vless", "port": 443},
    {"tag": "user-owned", "protocol": "socks", "port": 1080},
    {"tag": "api", "protocol": "dokodemo-door", "port": 10085}
  ],
  "outbounds": [{"protocol": "freedom"}]
}`)

	filtered, err := suppressConfiguredInbounds(original, map[string]struct{}{"managed": {}})
	if err != nil {
		t.Fatalf("suppress inbounds: %v", err)
	}
	if strings.Contains(string(filtered), `"tag":"managed"`) {
		t.Fatalf("filtered config still contains managed inbound: %s", filtered)
	}

	var config struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(filtered, &config); err != nil {
		t.Fatalf("decode filtered config: %v", err)
	}
	got := make([]string, 0, len(config.Inbounds))
	for _, inbound := range config.Inbounds {
		got = append(got, inbound.Tag)
	}
	if want := []string{"user-owned", "api"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("remaining inbound tags = %v, want %v", got, want)
	}
	if !strings.Contains(string(original), `"tag": "managed"`) {
		t.Fatal("suppression mutated the durable source buffer")
	}
}

func TestSuppressConfiguredInboundsRejectsMalformedInboundArray(t *testing.T) {
	_, err := suppressConfiguredInbounds([]byte(`{"inbounds": {}}`), map[string]struct{}{"managed": {}})
	if err == nil || !strings.Contains(err.Error(), "inbounds") {
		t.Fatalf("malformed inbounds error = %v, want inbounds parse error", err)
	}
}

func TestWireGuardStartupSuppressesInboundUntilPersistentMappingsComplete(t *testing.T) {
	config := []byte(`{
  "inbounds": [
    {
      "tag": "wg",
      "protocol": "wireguard",
      "settings": {
        "peers": [
          {"publicKey": "probe", "allowedIPs": ["10.66.0.1/32"]},
          {"publicKey": "alice", "allowedIPs": ["10.66.0.2/32"]}
        ]
      }
    },
    {"tag": "vless", "protocol": "vless", "settings": {"clients": []}}
  ]
}`)
	probeOnly := limiter.PersistentInboundSnapshot{
		InboundTag: "wg",
		Users: []limiter.UserInfo{
			{Email: "probe@relaydock.internal"},
		},
		WireGuardPeers: []limiter.WireGuardPeerUser{
			{Address: "10.66.0.1/32", Email: "probe@relaydock.internal"},
		},
	}
	complete := probeOnly
	complete.Users = append(append([]limiter.UserInfo(nil), probeOnly.Users...), limiter.UserInfo{Email: "alice@example.com"})
	complete.WireGuardPeers = append(append([]limiter.WireGuardPeerUser(nil), probeOnly.WireGuardPeers...), limiter.WireGuardPeerUser{
		Address: "10.66.0.2/32",
		Email:   "alice@example.com",
	})

	for _, test := range []struct {
		name      string
		snapshots []limiter.PersistentInboundSnapshot
		wantWG    bool
	}{
		{name: "legacy config without state", wantWG: true},
		{name: "incomplete state", snapshots: []limiter.PersistentInboundSnapshot{probeOnly}, wantWG: true},
		{name: "complete state", snapshots: []limiter.PersistentInboundSnapshot{complete}, wantWG: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			missing, err := wireGuardInboundTagsMissingPersistentMappings(config, test.snapshots)
			if err != nil {
				t.Fatal(err)
			}
			_, gotWG := missing["wg"]
			if gotWG != test.wantWG {
				t.Fatalf("missing mappings=%v; wg=%v want %v", missing, gotWG, test.wantWG)
			}
			if _, blocked := missing["vless"]; blocked {
				t.Fatalf("ordinary inbound was suppressed: %v", missing)
			}
		})
	}

	missing, err := wireGuardInboundTagsMissingPersistentMappings(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := suppressConfiguredInbounds(config, missing)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(filtered), `"tag":"wg"`) || !strings.Contains(string(filtered), `"tag":"vless"`) {
		t.Fatalf("legacy fail-closed suppression produced %s", filtered)
	}
}

func TestEmbeddedStartSuppressesLegacyWireGuardInboundWithoutPersistentState(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := []byte(`{
  "inbounds": [
    {
      "tag": "legacy-wg",
      "listen": "127.0.0.1",
      "port": 51820,
      "protocol": "wireguard",
      "settings": {
        "peers": [
          {"publicKey": "intentionally-invalid-unless-suppressed", "allowedIPs": ["10.66.0.2/32"]}
        ]
      }
    }
  ],
  "outbounds": [{"tag": "direct", "protocol": "freedom"}]
}`)
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	limiter.ConfigurePersistentSnapshotPath(filepath.Join(tempDir, "limiter-state.json"))
	t.Cleanup(func() { limiter.ConfigurePersistentSnapshotPath("") })

	xray := New(configPath)
	if err := xray.Start(); err != nil {
		t.Fatalf("Start with suppressed legacy WireGuard inbound: %v", err)
	}
	t.Cleanup(func() {
		if err := xray.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	manager, ok := xray.instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	if !ok || manager == nil {
		t.Fatal("embedded inbound manager is unavailable")
	}
	if _, err := manager.GetHandler(context.Background(), "legacy-wg"); err == nil {
		t.Fatal("legacy WireGuard inbound started without a persistent identity mapping")
	}
}

func TestEmbeddedStartRestoresAndStartsWireGuardInboundWithCompleteState(t *testing.T) {
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
      "tag": "wg",
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
	limiter.ConfigurePersistentSnapshotPath(filepath.Join(tempDir, "limiter-state.json"))
	t.Cleanup(func() { limiter.ConfigurePersistentSnapshotPath("") })
	if err := limiter.PersistInboundSnapshot(limiter.PersistentInboundSnapshot{
		InboundTag: "wg",
		Users:      []limiter.UserInfo{{Email: "alice@example.com"}},
		WireGuardPeers: []limiter.WireGuardPeerUser{
			{Address: "10.66.0.2/32", Email: "alice@example.com"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	xray := New(configPath)
	if err := xray.Start(); err != nil {
		t.Fatalf("Start with complete WireGuard limiter state: %v", err)
	}
	t.Cleanup(func() {
		if err := xray.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	manager, ok := xray.instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	if !ok || manager == nil {
		t.Fatal("embedded inbound manager is unavailable")
	}
	if _, err := manager.GetHandler(context.Background(), "wg"); err != nil {
		t.Fatalf("mapped WireGuard inbound was not started: %v", err)
	}
	if email, ok := xray.GetLimiter().ResolveWireGuardPeerUser("wg", "10.66.0.2"); !ok || email != "alice@example.com" {
		t.Fatalf("restored WireGuard identity=%q, %v", email, ok)
	}
}
