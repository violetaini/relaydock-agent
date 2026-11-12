package conf

import (
	"encoding/json"
	"github.com/violetaini/chitanda/pkg/server"
	"github.com/xtls/xray-core/proxy/chitanda"
	"testing"
)

func TestChitandaOutboundScalerJSON(t *testing.T) {
	var cfg ChitandaOutboundConfig
	data := []byte(`{"server":"example.com:443","psk":"test-only-key-that-is-at-least-32-bytes","transport":"h3","pool_size":2,"auto_scale":true,"max_pool_size":8}`)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	message, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	outbound := message.(*chitanda.OutboundConfig)
	if !outbound.AutoScale || outbound.MaxPoolSize != 8 {
		t.Fatalf("JSON scaler settings were lost: auto_scale=%v max_pool_size=%d", outbound.AutoScale, outbound.MaxPoolSize)
	}
}

func TestChitandaTLSInheritanceAndDefaults(t *testing.T) {
	c := ChitandaInboundConfig{PSK: "test-only-key-that-is-at-least-32-bytes", Transport: "h3"}
	c.InheritTLS(&StreamConfig{TLSSettings: &TLSConfig{Certs: []*TLSCertConfig{{CertFile: "server.pem", KeyFile: "server.key"}}}})
	m, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	cfg := m.(*chitanda.InboundConfig)
	if cfg.CertFile != "server.pem" || cfg.KeyFile != "server.key" || cfg.Path != "/api/v1/sync" {
		t.Fatal("inheritance/default failed")
	}
	c.InheritTLS(&StreamConfig{TLSSettings: &TLSConfig{Certs: []*TLSCertConfig{{CertFile: "other.pem", KeyFile: "other.key"}}}})
	if c.CertFile != "server.pem" {
		t.Fatal("explicit certificate overwritten")
	}
	out := ChitandaOutboundConfig{Server: "example.com:443", PSK: c.PSK}
	om, err := out.Build()
	if err != nil {
		t.Fatal(err)
	}
	if om.(*chitanda.OutboundConfig).ServerName != "example.com" {
		t.Fatal("server_name default lost")
	}
	if _, err := (&ChitandaInboundConfig{PSK: c.PSK, CertFile: "only-cert"}).Build(); err == nil {
		t.Fatal("incomplete key pair accepted")
	}
	if _, err := (&ChitandaOutboundConfig{PSK: c.PSK, Server: "example.com:443", Transport: "typo"}).Build(); err == nil {
		t.Fatal("invalid transport accepted")
	}
}

func TestChitandaMultiUserConfig(t *testing.T) {
	// 1. Valid multi-user config
	validCfg := ChitandaInboundConfig{
		Transport: "h2",
		Users: []*ChitandaUser{
			{Email: "alice@chitanda.org", PSK: "alice-key-at-least-32-bytes-long!", Level: 1},
			{Email: "bob@chitanda.org", PSK: "bob---key-at-least-32-bytes-long!", Level: 2},
		},
	}
	m, err := validCfg.Build()
	if err != nil {
		t.Fatalf("valid multi-user build failed: %v", err)
	}
	cfg := m.(*chitanda.InboundConfig)
	if len(cfg.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(cfg.Users))
	}
	if cfg.Users[0].Email != "alice@chitanda.org" || cfg.Users[0].Level != 1 {
		t.Fatalf("alice config mismatch: %v", cfg.Users[0])
	}
	if cfg.Users[1].Email != "bob@chitanda.org" || cfg.Users[1].Level != 2 {
		t.Fatalf("bob config mismatch: %v", cfg.Users[1])
	}

	// 2. Reject empty email
	emptyEmailCfg := ChitandaInboundConfig{
		Transport: "h2",
		Users: []*ChitandaUser{
			{Email: "   ", PSK: "alice-key-at-least-32-bytes-long!"},
		},
	}
	if _, err := emptyEmailCfg.Build(); err == nil {
		t.Fatal("expected error for empty email, got nil")
	}

	// 3. Reject duplicate email (case-insensitive)
	dupEmailCfg := ChitandaInboundConfig{
		Transport: "h2",
		Users: []*ChitandaUser{
			{Email: "alice@chitanda.org", PSK: "alice-key-at-least-32-bytes-long!"},
			{Email: "ALICE@chitanda.org", PSK: "other-key-at-least-32-bytes-long!"},
		},
	}
	if _, err := dupEmailCfg.Build(); err == nil {
		t.Fatal("expected error for duplicate email, got nil")
	}

	// 4. Reject short PSK
	shortPSKCfg := ChitandaInboundConfig{
		Transport: "h2",
		Users: []*ChitandaUser{
			{Email: "bob@chitanda.org", PSK: "short-psk"},
		},
	}
	if _, err := shortPSKCfg.Build(); err == nil {
		t.Fatal("expected error for short PSK, got nil")
	}

	// 5. Reject duplicate PSK
	dupPSKCfg := ChitandaInboundConfig{
		Transport: "h2",
		Users: []*ChitandaUser{
			{Email: "alice@chitanda.org", PSK: "shared-key-at-least-32-bytes-long!"},
			{Email: "bob@chitanda.org", PSK: "shared-key-at-least-32-bytes-long!"},
		},
	}
	if _, err := dupPSKCfg.Build(); err == nil {
		t.Fatal("expected error for duplicate PSK, got nil")
	}

	// 6. Reject users list with only nil entries
	nilUsersCfg := ChitandaInboundConfig{
		Transport: "h2",
		Users:     []*ChitandaUser{nil},
	}
	if _, err := nilUsersCfg.Build(); err == nil {
		t.Fatal("expected error for nil users list, got nil")
	}
	for name, invalid := range map[string]ChitandaInboundConfig{
		"mixed psk and users": {PSK: "0123456789abcdef0123456789abcdef", Users: validCfg.Users},
		"partially nil users": {Users: []*ChitandaUser{validCfg.Users[0], nil}},
		"too many users":      {Users: make([]*ChitandaUser, server.MaxUserKeys+1)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := invalid.Build(); err == nil {
				t.Fatal("invalid user config was accepted")
			}
		})
	}
}
