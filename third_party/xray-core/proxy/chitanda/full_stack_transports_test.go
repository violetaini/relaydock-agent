package chitanda_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	"github.com/xtls/xray-core/core"
)

// Real JSON loader -> Xray inbound/dispatcher -> TCP/UDP echo. No production
// credentials, traffic, configuration or fixed public ports are involved.
func TestChitandaFullStackAllTransportsConcurrentAndIdle(t *testing.T) {
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
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		var b [2048]byte
		for {
			n, addr, err := udpEcho.ReadFromUDP(b[:])
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteToUDP(b[:n], addr)
		}
	}()
	for _, mode := range []string{"stream", "h1", "h2", "h3", "auto"} {
		t.Run(mode, func(t *testing.T) {
			reservation, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := reservation.Addr().(*net.TCPAddr).Port
			_ = reservation.Close()
			psk := bytes.Repeat([]byte{'x'}, 32) // JSON PSK is UTF-8 text, not arbitrary binary.
			settings := map[string]any{"transport": mode, "psk": string(psk), "path": "/all-modes", "server_id": "all-modes", "cert_file": certPath, "key_file": keyPath, "replay_file": filepath.Join(dir, mode+".cache")}
			config, err := json.Marshal(map[string]any{
				"log":       map[string]any{"loglevel": "warning"},
				"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "chitanda", "settings": settings}},
				"outbounds": []any{map[string]any{"protocol": "freedom"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			instance, err := core.StartInstance("json", config)
			if err != nil {
				t.Fatal(err)
			}
			defer instance.Close()
			c, err := client.New(client.Config{Server: fmt.Sprintf("127.0.0.1:%d", port), ServerName: "localhost", Path: "/all-modes", ServerID: "all-modes", PSK: psk, TCPTransport: mode, TCPPoolSize: 2, UDPPoolSize: 2, InsecureSkipVerify: true})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var connections []net.Conn
			for range 4 {
				conn, err := c.DialContext(ctx, "tcp", tcpEcho.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
				if _, err := conn.Write([]byte("before")); err != nil {
					t.Fatal(err)
				}
				var b [6]byte
				if _, err := io.ReadFull(conn, b[:]); err != nil || string(b[:]) != "before" {
					t.Fatalf("before idle: %q %v", b, err)
				}
				connections = append(connections, conn)
			}
			time.Sleep(6 * time.Second) // Explicit idle recovery requirement, not test synchronization.
			var wg sync.WaitGroup
			for i, conn := range connections {
				wg.Add(1)
				go func(i int, conn net.Conn) {
					defer wg.Done()
					p := bytes.Repeat([]byte{byte(i)}, 32<<10)
					if _, err := conn.Write(p); err != nil {
						t.Error(err)
						return
					}
					b := make([]byte, len(p))
					if _, err := io.ReadFull(conn, b); err != nil || !bytes.Equal(p, b) {
						t.Errorf("concurrent TCP: %v", err)
					}
				}(i, conn)
			}
			wg.Wait()
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					pc, err := c.ListenPacket(ctx)
					if err != nil {
						t.Error(err)
						return
					}
					defer pc.Close()
					_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
					p := bytes.Repeat([]byte{byte(i + 1)}, 1200)
					for range 8 {
						if _, err := pc.WriteTo(p, udpEcho.LocalAddr()); err != nil {
							t.Error(err)
							return
						}
						var b [1500]byte
						n, _, err := pc.ReadFrom(b[:])
						if err != nil || !bytes.Equal(p, b[:n]) {
							t.Errorf("concurrent UDP: %v", err)
							return
						}
					}
				}(i)
			}
			wg.Wait()
		})
	}
}
