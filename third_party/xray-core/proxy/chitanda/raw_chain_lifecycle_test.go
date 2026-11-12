package chitanda_test

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
)

// ProxySettings starts a real forwarding task using the SDK dial context.
// It must survive successful TCP/UDP handoff, and end when the core closes.
func TestChitandaProxyChainAllTransportsSurvivesDialHandoff(t *testing.T) {
	tlsFixture := httptest.NewTLSServer(nil)
	certificate := tlsFixture.TLS.Certificates[0]
	tlsFixture.Close()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	tcpEcho, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	go func() {
		for {
			conn, err := tcpEcho.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	echoPort := tcpEcho.Addr().(*net.TCPAddr).Port
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: echoPort})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		var p [1024]byte
		for {
			n, addr, err := udpEcho.ReadFromUDP(p[:])
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteToUDP(p[:n], addr)
		}
	}()

	for _, mode := range []string{"stream", "h1", "h2", "h3", "auto"} {
		t.Run(mode, func(t *testing.T) {
			psk := bytes.Repeat([]byte{'x'}, 32)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			remotePort := listener.Addr().(*net.TCPAddr).Port
			remoteConfig, err := json.Marshal(map[string]any{
				"log":       map[string]any{"loglevel": "warning"},
				"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": remotePort, "protocol": "chitanda", "settings": map[string]any{"transport": mode, "psk": string(psk), "path": "/chain", "replay_file": t.TempDir() + "/remote.cache", "cert_file": certPath, "key_file": keyPath}}},
				"outbounds": []any{map[string]any{"protocol": "freedom"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			_ = listener.Close()
			remoteCore, err := core.StartInstance("json", remoteConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer remoteCore.Close()
			reserve, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			localPort := reserve.Addr().(*net.TCPAddr).Port
			_ = reserve.Close()
			config, err := json.Marshal(map[string]any{
				"log":      map[string]any{"loglevel": "warning"},
				"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": localPort, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1", "port": echoPort, "network": "tcp,udp"}}},
				"outbounds": []any{
					map[string]any{"tag": "chitanda", "protocol": "chitanda", "settings": map[string]any{"server": net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), "server_name": "localhost", "allow_insecure": true, "pool_size": 1, "psk": string(psk), "transport": mode, "path": "/chain"}, "streamSettings": map[string]any{"sockopt": map[string]any{"dialerProxy": "chain-direct"}}},
					map[string]any{"tag": "chain-direct", "protocol": "freedom"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			localCore, err := core.StartInstance("json", config)
			if err != nil {
				t.Fatal(err)
			}
			defer localCore.Close()
			for _, network := range []string{"tcp", "udp"} {
				t.Run(network, func(t *testing.T) {
					var connections []net.Conn
					for range 3 {
						conn, err := net.Dial(network, net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)))
						if err != nil {
							t.Fatal(err)
						}
						defer conn.Close()
						connections = append(connections, conn)
					}
					echo := func(conn net.Conn) {
						t.Helper()
						for range 3 {
							_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
							if _, err := conn.Write([]byte("chain-echo")); err != nil {
								t.Fatalf("%s write: %v", network, err)
							}
							var got [10]byte
							if _, err := io.ReadFull(conn, got[:]); err != nil || string(got[:]) != "chain-echo" {
								t.Fatalf("%s echo=%q err=%v", network, got, err)
							}
						}
					}
					for _, conn := range connections {
						echo(conn)
					}
					// Ending the flow that created the shared carrier must not cancel
					// the embedding Dispatcher underneath its remaining siblings.
					_ = connections[0].Close()
					for _, conn := range connections[1:] {
						echo(conn)
					}
				})
			}
		})
	}
}
