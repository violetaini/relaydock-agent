package handler

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This test is opt-in because it starts the host/container's default Nginx.
// CI runs it inside a disposable official Nginx image.
func TestNginxReuseExistingWithSystemNginx(t *testing.T) {
	if os.Getenv("ARCWAY_NGINX_INTEGRATION") != "1" {
		t.Skip("set ARCWAY_NGINX_INTEGRATION=1 inside a disposable Nginx environment")
	}

	binary := findNginxBinary()
	if binary == "" {
		t.Fatal("system nginx binary not found")
	}
	if output, err := exec.Command(binary, "-t").CombinedOutput(); err != nil {
		t.Fatalf("baseline nginx -t failed: %s: %v", strings.TrimSpace(string(output)), err)
	}
	if err := exec.Command(binary).Run(); err != nil {
		t.Fatalf("start system nginx: %v", err)
	}
	defer func() { _ = exec.Command(binary, "-s", "quit").Run() }()

	result, err := setupNginxReuseExisting("reuse.arcway.test", `server {
    listen 127.0.0.1:18080;
    server_name reuse.arcway.test;
    location / { return 200 "arcway-reuse-ok"; }
}`)
	if err != nil {
		t.Fatalf("setup reuse_existing: %v", err)
	}
	defer func() {
		_ = os.Remove(result.ConfigPath)
		_ = os.Remove(result.LoaderPath)
		_ = os.Remove(nginxReusePrivateRoot(result.MainConfigPath) + "/servers")
		_ = os.Remove(nginxReusePrivateRoot(result.MainConfigPath))
		_ = exec.Command(binary, "-s", "reload").Run()
	}()

	dump, err := exec.Command(binary, "-T").CombinedOutput()
	if err != nil {
		t.Fatalf("render active nginx configuration: %s: %v", strings.TrimSpace(string(dump)), err)
	}
	if !strings.Contains(string(dump), arcwayReuseLoaderMarker) || !strings.Contains(string(dump), arcwayReuseConfigMarker) {
		t.Fatalf("active nginx configuration does not contain Arcway ownership markers")
	}

	client := &http.Client{Timeout: time.Second}
	var responseBody string
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		response, requestErr := client.Get("http://127.0.0.1:18080/")
		if requestErr != nil {
			continue
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr == nil && response.StatusCode == http.StatusOK {
			responseBody = string(body)
			break
		}
	}
	if responseBody != "arcway-reuse-ok" {
		t.Fatalf("reused system nginx did not serve the Arcway site: body=%q", responseBody)
	}
}
