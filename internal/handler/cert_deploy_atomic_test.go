package handler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestDeployCertFilesUsesSecureModes(t *testing.T) {
	certPEM, keyPEM := generateCertDeployPEM(t)
	root := t.TempDir()
	certPath := filepath.Join(root, "tls", "cert.pem")
	keyPath := filepath.Join(root, "tls", "key.pem")

	deployment, err := deployCertFiles(certPEM, keyPEM, certPath, keyPath)
	if err != nil {
		t.Fatalf("deploy certificate pair: %v", err)
	}
	assertCertDeployFile(t, certPath, certPEM, 0o644)
	assertCertDeployFile(t, keyPath, keyPEM, 0o600)
	if err := deployment.Rollback(); err != nil {
		t.Fatalf("rollback new certificate pair: %v", err)
	}
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("rollback did not remove newly created %s: %v", path, err)
		}
	}
}

func TestDeployCertFilesStageFailureLeavesExistingPairUntouched(t *testing.T) {
	certPEM, keyPEM := generateCertDeployPEM(t)
	certPath, keyPath, oldCert, oldKey := writeExistingCertPair(t)
	createCalls := 0
	ops := defaultCertFileOps()
	ops.createTemp = func(dir, pattern string) (*os.File, error) {
		createCalls++
		if createCalls == 2 {
			return nil, errors.New("injected key staging failure")
		}
		return os.CreateTemp(dir, pattern)
	}

	if _, err := deployCertFilesWithOps(certPEM, keyPEM, certPath, keyPath, ops); err == nil || !strings.Contains(err.Error(), "staging failure") {
		t.Fatalf("deploy error = %v, want injected staging failure", err)
	}
	assertCertDeployFile(t, certPath, oldCert, 0o600)
	assertCertDeployFile(t, keyPath, oldKey, 0o640)
	assertNoCertDeployTemps(t, filepath.Dir(certPath))
}

func TestDeployCertFilesSecondReplaceFailureRestoresExistingPair(t *testing.T) {
	certPEM, keyPEM := generateCertDeployPEM(t)
	certPath, keyPath, oldCert, oldKey := writeExistingCertPair(t)
	ops := defaultCertFileOps()
	ops.rename = func(oldPath, newPath string) error {
		if newPath == keyPath {
			return errors.New("injected key replacement failure")
		}
		return os.Rename(oldPath, newPath)
	}

	if _, err := deployCertFilesWithOps(certPEM, keyPEM, certPath, keyPath, ops); err == nil || !strings.Contains(err.Error(), "replacement failure") {
		t.Fatalf("deploy error = %v, want injected replacement failure", err)
	}
	assertCertDeployFile(t, certPath, oldCert, 0o600)
	assertCertDeployFile(t, keyPath, oldKey, 0o640)
	assertNoCertDeployTemps(t, filepath.Dir(certPath))
}

func TestHandleCertDeployXrayReloadFailureRollsBackPair(t *testing.T) {
	certPEM, keyPEM := generateCertDeployPEM(t)
	certPath, keyPath, oldCert, oldKey := writeExistingCertPair(t)
	handler := NewManageHandler("", "custom", "exit 1")
	handler.SetXrayMode("external")
	handler.xrayStatusResolver = func() *ServiceStatus {
		return &ServiceStatus{Installed: true, Running: true}
	}
	payload, err := json.Marshal(CertDeployRequest{
		Domain:   "example.com",
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		CertPath: certPath,
		KeyPath:  keyPath,
		Reload:   "xray",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, constants.PathChildCertDeploy, bytes.NewReader(payload))
	request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
	response := httptest.NewRecorder()

	handler.HandleCertDeploy(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "xray reload failed") {
		t.Fatalf("response did not report xray reload failure: %s", response.Body.String())
	}
	assertCertDeployFile(t, certPath, oldCert, 0o600)
	assertCertDeployFile(t, keyPath, oldKey, 0o640)
	assertNoCertDeployTemps(t, filepath.Dir(certPath))
}

func TestHandleCertDeployDoesNotStartStoppedXray(t *testing.T) {
	certPEM, keyPEM := generateCertDeployPEM(t)
	certPath, keyPath, _, _ := writeExistingCertPair(t)
	restartMarker := filepath.Join(t.TempDir(), "xray-restarted")
	handler := NewManageHandler("", "custom", "printf restarted > "+restartMarker)
	handler.SetXrayMode("external")
	handler.xrayStatusResolver = func() *ServiceStatus {
		return &ServiceStatus{Installed: true, Running: false}
	}
	payload, err := json.Marshal(CertDeployRequest{
		Domain:   "example.com",
		CertPEM:  certPEM,
		KeyPEM:   keyPEM,
		CertPath: certPath,
		KeyPath:  keyPath,
		Reload:   "xray",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, constants.PathChildCertDeploy, bytes.NewReader(payload))
	request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
	response := httptest.NewRecorder()

	handler.HandleCertDeploy(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(restartMarker); !os.IsNotExist(err) {
		t.Fatalf("stopped Xray was unexpectedly restarted: %v", err)
	}
	if !strings.Contains(response.Body.String(), "reload deferred") {
		t.Fatalf("response did not report deferred reload: %s", response.Body.String())
	}
	assertCertDeployFile(t, certPath, certPEM, 0o644)
	assertCertDeployFile(t, keyPath, keyPEM, 0o600)
}

func TestHandleAutomaticCertDeployDoesNotRestartRunningXray(t *testing.T) {
	certPEM, keyPEM := generateCertDeployPEM(t)
	certPath, keyPath, _, _ := writeExistingCertPair(t)
	restartMarker := filepath.Join(t.TempDir(), "xray-restarted")
	handler := NewManageHandler("", "custom", "printf restarted > "+restartMarker)
	handler.SetXrayMode("external")
	handler.xrayStatusResolver = func() *ServiceStatus {
		return &ServiceStatus{Installed: true, Running: true}
	}
	payload, err := json.Marshal(CertDeployRequest{
		Domain:    "example.com",
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		CertPath:  certPath,
		KeyPath:   keyPath,
		Reload:    "xray",
		Automatic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, constants.PathChildCertDeploy, bytes.NewReader(payload))
	request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
	response := httptest.NewRecorder()

	handler.HandleCertDeploy(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(restartMarker); !os.IsNotExist(err) {
		t.Fatalf("automatic certificate deployment restarted Xray: %v", err)
	}
	if !strings.Contains(response.Body.String(), "automatic Xray reload suppressed") {
		t.Fatalf("response did not report suppressed reload: %s", response.Body.String())
	}
	assertCertDeployFile(t, certPath, certPEM, 0o644)
	assertCertDeployFile(t, keyPath, keyPEM, 0o600)
}

func TestReloadRunningXrayForCertificateDoesNotStartStoppedXray(t *testing.T) {
	restartMarker := filepath.Join(t.TempDir(), "xray-restarted")
	handler := NewManageHandler("", "custom", "printf restarted > "+restartMarker)
	handler.SetXrayMode("external")
	handler.xrayStatusResolver = func() *ServiceStatus {
		return &ServiceStatus{Installed: true, Running: false}
	}

	if err := handler.ReloadRunningXrayForCertificate(); err != nil {
		t.Fatalf("reload stopped Xray: %v", err)
	}
	if _, err := os.Stat(restartMarker); !os.IsNotExist(err) {
		t.Fatalf("stopped Xray was unexpectedly restarted: %v", err)
	}
}

func writeExistingCertPair(t *testing.T) (certPath, keyPath, certContent, keyContent string) {
	t.Helper()
	root := t.TempDir()
	certPath = filepath.Join(root, "tls", "cert.pem")
	keyPath = filepath.Join(root, "tls", "key.pem")
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		t.Fatal(err)
	}
	certContent = "old certificate\n"
	keyContent = "old private key\n"
	if err := os.WriteFile(certPath, []byte(certContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyContent), 0o640); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, certContent, keyContent
}

func assertCertDeployFile(t *testing.T, path, wantContent string, wantMode os.FileMode) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(content) != wantContent {
		t.Fatalf("content of %s = %q, want %q", path, content, wantContent)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != wantMode {
		t.Fatalf("mode of %s = %04o, want %04o", path, got, wantMode)
	}
}

func assertNoCertDeployTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".arcway-cert-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("staged certificate files were not cleaned up: %v", matches)
	}
}

func generateCertDeployPEM(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}
