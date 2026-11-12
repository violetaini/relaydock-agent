package embedded

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func reserveFreeTCPAndUDPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestEmbeddedChitandaProtocolConfigAndStart(t *testing.T) {
	port := reserveFreeTCPAndUDPPort(t)
	apiPort := reserveFreeTCPAndUDPPort(t)
	if apiPort == port {
		apiPort = reserveFreeTCPAndUDPPort(t)
	}

	psk := "chitanda-embedded-test-psk-0123456789abcdef"
	cfg := fmt.Sprintf(`{
  "api": {"services": ["HandlerService", "StatsService"], "tag": "api"},
  "inbounds": [
    {"listen": "127.0.0.1", "port": %d, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}, "tag": "api"},
    {"listen": "127.0.0.1", "port": %d, "protocol": "chitanda", "settings": {"psk": %q, "transport": "stream", "path": "/api/v1/sync"}, "tag": "inbound-%d"}
  ],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "chitanda-out", "protocol": "chitanda", "settings": {"server": "127.0.0.1:%d", "server_name": "localhost", "psk": %q, "transport": "stream", "allow_insecure": true}}
  ]
}`, apiPort, port, psk, port, port, psk)

	if err := TestConfigJSON([]byte(cfg)); err != nil {
		t.Fatalf("TestConfigJSON failed on chitanda config: %v", err)
	}

	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	ex := New(cfgPath)
	if err := ex.Start(); err != nil {
		t.Fatalf("EmbeddedXray.Start failed on chitanda config: %v", err)
	}
	defer func() {
		if err := ex.Stop(); err != nil {
			t.Fatalf("EmbeddedXray.Stop failed: %v", err)
		}
	}()

	if !ex.IsRunning() {
		t.Fatal("expected EmbeddedXray to report running")
	}
}
