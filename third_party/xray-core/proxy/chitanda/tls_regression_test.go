package chitanda

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"google.golang.org/protobuf/proto"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Test certificates are explicit fixtures, never a production fallback.
func generateSelfSignedCert(_ string) (tls.Certificate, error) {
	s := httptest.NewTLSServer(nil)
	defer s.Close()
	return s.TLS.Certificates[0], nil
}

func testTLSConfig(t *testing.T, config *InboundConfig) *InboundConfig {
	t.Helper()
	copyConfig := proto.Clone(config).(*InboundConfig)
	c, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	copyConfig.CertFile = filepath.Join(dir, "cert.pem")
	copyConfig.KeyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(copyConfig.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyConfig.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	return copyConfig
}

func newTestInboundHandler(t *testing.T, ctx context.Context, cfg *InboundConfig) (*InboundHandler, error) {
	t.Helper()
	if cfg.ReplayFile == "" {
		copyConfig := proto.Clone(cfg).(*InboundConfig)
		copyConfig.ReplayFile = filepath.Join(t.TempDir(), "replay.cache")
		cfg = copyConfig
	}
	if cfg.Transport != "stream" && cfg.Transport != "h1" && cfg.Transport != "plain-h1" {
		cfg = testTLSConfig(t, cfg)
	}
	return NewInboundHandler(ctx, cfg)
}

func TestTLSRequiresExplicitCertificate(t *testing.T) {
	for _, cfg := range []*InboundConfig{{}, {CertFile: "missing"}, {KeyFile: "missing"}} {
		if _, err := buildServerTLSConfig(cfg); err == nil {
			t.Fatal("missing certificate pair accepted")
		}
	}
}
