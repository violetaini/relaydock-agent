package handler

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestHandleCheckPortDetectsConfigInboundAndOSListeners(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.json")
	cfgJSON := `{
		"inbounds": [
			{"tag": "vless-in", "port": 24443, "protocol": "vless"},
			{"tag": "wg-in", "port": 51820, "protocol": "wireguard"}
		]
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	h := NewManageHandler("secret-token", "custom", "true")
	h.inboundMutationConfigPathResolver = func() string { return cfgPath }
	h.SetListenPort(23889)
	h.portAvailabilityProbe = func(port int, networks []string) (bool, string, string) {
		return true, "", ""
	}

	check := func(query string) (int, portCheckResponse) {
		req := httptest.NewRequest(http.MethodGet, constants.PathChildPortsCheck+query, nil)
		req.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
		req.Header.Set("Authorization", "Bearer secret-token")
		rec := httptest.NewRecorder()
		h.HandleCheckPort(rec, req)
		var out portCheckResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	// Agent's own listen port must be rejected on tcp/tcp,udp even if probe says free (WS stealth closed socket).
	code, resp := check("?port=23889&network=tcp,udp")
	if code != http.StatusOK || resp.Available || resp.OccupiedBy != "agent_port" {
		t.Fatalf("expected agent_port conflict on 23889, got code=%d resp=%+v", code, resp)
	}

	// Configured TCP-only inbound blocks tcp, allows udp-only if OS is free.
	code, resp = check("?port=24443&network=tcp")
	if code != http.StatusOK || resp.Available || resp.OccupiedBy != "xray_inbound" || resp.Tag != "vless-in" {
		t.Fatalf("expected xray_inbound conflict on 24443 tcp, got code=%d resp=%+v", code, resp)
	}
	code, resp = check("?port=24443&network=udp")
	if code != http.StatusOK || !resp.Available {
		t.Fatalf("expected 24443 udp available, got code=%d resp=%+v", code, resp)
	}
	// Editing same tag can ignore itself.
	code, resp = check("?port=24443&network=tcp&ignore_tag=vless-in")
	if code != http.StatusOK || !resp.Available {
		t.Fatalf("expected ignore_tag to pass, got code=%d resp=%+v", code, resp)
	}

	// Real OS TCP + UDP socket probe using an ephemeral port.
	h.portAvailabilityProbe = nil
	tcpLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	busyTCPPort := tcpLn.Addr().(*net.TCPAddr).Port
	code, resp = check(fmt.Sprintf("?port=%d&network=tcp,udp", busyTCPPort))
	if code != http.StatusOK || resp.Available || resp.OccupiedBy != "system_listener" || resp.Network != "tcp" {
		_ = tcpLn.Close()
		t.Fatalf("expected live TCP listener conflict on %d, got code=%d resp=%+v", busyTCPPort, code, resp)
	}
	_ = tcpLn.Close()

	udpPC, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen udp4: %v", err)
	}
	busyUDPPort := udpPC.LocalAddr().(*net.UDPAddr).Port
	code, resp = check(fmt.Sprintf("?port=%d&network=tcp,udp", busyUDPPort))
	if code != http.StatusOK || resp.Available || resp.OccupiedBy != "system_listener" || resp.Network != "udp" {
		_ = udpPC.Close()
		t.Fatalf("expected live UDP listener conflict on %d, got code=%d resp=%+v", busyUDPPort, code, resp)
	}
	_ = udpPC.Close()

	// When Xray is actively holding its own port, editing that inbound with ignore_tag passes OS probe.
	selfLn, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen self tcp4: %v", err)
	}
	selfPort := selfLn.Addr().(*net.TCPAddr).Port
	cfgWithSelf := fmt.Sprintf(`{
		"inbounds": [
			{"tag": "vless-in", "port": 24443, "protocol": "vless"},
			{"tag": "wg-in", "port": 51820, "protocol": "wireguard"},
			{"tag": "self-in", "port": %d, "protocol": "shadowsocks"}
		]
	}`, selfPort)
	if err := os.WriteFile(cfgPath, []byte(cfgWithSelf), 0600); err != nil {
		_ = selfLn.Close()
		t.Fatalf("rewrite config: %v", err)
	}
	h.xrayRunningProbe = func() bool { return false }
	code, resp = check(fmt.Sprintf("?port=%d&network=tcp&ignore_tag=self-in", selfPort))
	if code != http.StatusOK || resp.Available || resp.OccupiedBy != "system_listener" {
		_ = selfLn.Close()
		t.Fatalf("expected stopped xray not to mask OS listener on %d, got code=%d resp=%+v", selfPort, code, resp)
	}
	h.xrayRunningProbe = func() bool { return true }
	code, resp = check(fmt.Sprintf("?port=%d&network=tcp&ignore_tag=self-in", selfPort))
	if code != http.StatusOK || !resp.Available {
		_ = selfLn.Close()
		t.Fatalf("expected running xray ignore_tag to pass OS probe on %d, got code=%d resp=%+v", selfPort, code, resp)
	}
	_ = selfLn.Close()

	// Invalid port rejected.
	code, _ = check("?port=70000")
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid port, got %d", code)
	}
}
