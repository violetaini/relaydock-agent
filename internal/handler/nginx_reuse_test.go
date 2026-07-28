package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mmw-agent/internal/constants"
)

func TestNginxHTTPIncludePatternsExcludesStreamIncludes(t *testing.T) {
	dump := `events {}
http {
    include /etc/nginx/conf.d/*.conf;
    server { include /etc/nginx/snippets/location.conf; }
}
stream {
    include /etc/nginx/stream-conf.d/*.conf;
}
include /etc/nginx/modules-enabled/*.conf;
`

	got := nginxHTTPIncludePatterns(dump)
	if len(got) != 2 {
		t.Fatalf("got %d HTTP includes, want 2: %#v", len(got), got)
	}
	if got[0] != "/etc/nginx/conf.d/*.conf" || got[1] != "/etc/nginx/snippets/location.conf" {
		t.Fatalf("unexpected HTTP includes: %#v", got)
	}
}

func TestTryNginxReuseCandidateReloadsBeforeVerifyingRenderedConfig(t *testing.T) {
	root := t.TempDir()
	includeDir := filepath.Join(root, "conf.d")
	if err := os.MkdirAll(includeDir, 0755); err != nil {
		t.Fatal(err)
	}

	var calls []string
	runtime := nginxReuseRuntime{Binary: "fake-nginx", MainConfigPath: filepath.Join(root, "nginx.conf")}
	candidate := nginxIncludeCandidate{Pattern: filepath.Join(includeDir, "*.conf"), LoaderPath: filepath.Join(includeDir, "arcway-reuse.conf")}
	domainPath := filepath.Join(root, "arcway.d", "servers", "example.com.conf")

	originalRun := runNginxForReuse
	runNginxForReuse = func(_ string, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if len(args) == 1 && args[0] == "-T" {
			loader, loaderErr := os.ReadFile(candidate.LoaderPath)
			domain, domainErr := os.ReadFile(domainPath)
			if loaderErr != nil || domainErr != nil {
				return "", fmt.Errorf("Arcway files were not present during -T")
			}
			return string(loader) + string(domain), nil
		}
		return "", nil
	}
	t.Cleanup(func() { runNginxForReuse = originalRun })

	_, err := tryNginxReuseCandidate(runtime, candidate, domainPath, renderNginxReuseLoader(filepath.Dir(domainPath)), renderNginxReuseDomainConfig("server {}\n"), false, false)
	if err != nil {
		t.Fatalf("tryNginxReuseCandidate: %v", err)
	}
	want := []string{"-t", "-s reload", "-T"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("nginx calls = %#v, want %#v", calls, want)
	}
}

func TestTryNginxReuseCandidateRollsBackAfterRenderedVerificationFailure(t *testing.T) {
	root := t.TempDir()
	includeDir := filepath.Join(root, "conf.d")
	if err := os.MkdirAll(includeDir, 0755); err != nil {
		t.Fatal(err)
	}

	var calls []string
	runtime := nginxReuseRuntime{Binary: "fake-nginx", MainConfigPath: filepath.Join(root, "nginx.conf")}
	candidate := nginxIncludeCandidate{Pattern: filepath.Join(includeDir, "*.conf"), LoaderPath: filepath.Join(includeDir, "arcway-reuse.conf")}
	domainPath := filepath.Join(root, "arcway.d", "servers", "example.com.conf")

	originalRun := runNginxForReuse
	runNginxForReuse = func(_ string, args ...string) (string, error) {
		calls = append(calls, strings.Join(args, " "))
		if len(args) == 1 && args[0] == "-T" {
			return "configuration without Arcway", nil
		}
		return "", nil
	}
	t.Cleanup(func() { runNginxForReuse = originalRun })

	_, err := tryNginxReuseCandidate(runtime, candidate, domainPath, renderNginxReuseLoader(filepath.Dir(domainPath)), renderNginxReuseDomainConfig("server {}\n"), false, false)
	if err == nil || !strings.Contains(err.Error(), "Arcway files restored") {
		t.Fatalf("expected rollback error, got %v", err)
	}
	if _, statErr := os.Stat(candidate.LoaderPath); !os.IsNotExist(statErr) {
		t.Fatalf("loader remains after rollback: %v", statErr)
	}
	if _, statErr := os.Stat(domainPath); !os.IsNotExist(statErr) {
		t.Fatalf("domain config remains after rollback: %v", statErr)
	}
	want := []string{"-t", "-s reload", "-T", "-t", "-s reload"}
	if strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("nginx calls = %#v, want %#v", calls, want)
	}
}

func TestEnsureNginxReuseDirectoryRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "arcway.d")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureNginxReuseDirectory(link); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("symlink was accepted: %v", err)
	}
}

func TestReuseExistingRejectsNginxControlAndLeavesStreamFilesAlone(t *testing.T) {
	h := NewManageHandler("test-token", "auto", "")
	h.SetNginxMode(constants.NginxModeReuseExisting)

	for _, handler := range []http.HandlerFunc{h.HandleNginxInstall, h.HandleNginxRemove, h.HandleNginxInstallStream, h.HandleNginxRemoveStream} {
		req := authenticatedRequest(t, http.MethodPost, "/", "{}")
		recorder := httptest.NewRecorder()
		handler(recorder, req)
		if recorder.Code != http.StatusConflict {
			t.Fatalf("nginx mutation status = %d, want %d: %s", recorder.Code, http.StatusConflict, recorder.Body.String())
		}
	}

	originalPrefix := constants.NginxPrimaryPrefixDir
	constants.NginxPrimaryPrefixDir = t.TempDir()
	t.Cleanup(func() { constants.NginxPrimaryPrefixDir = originalPrefix })
	streamDir := filepath.Join(constants.NginxPrimaryPrefixDir, "stream_servers")
	if err := os.MkdirAll(streamDir, 0755); err != nil {
		t.Fatal(err)
	}
	streamFile := filepath.Join(streamDir, "external.conf")
	if err := os.WriteFile(streamFile, []byte("listen 443;\n"), 0644); err != nil {
		t.Fatal(err)
	}

	req := authenticatedRequest(t, http.MethodPost, "/", `{"port":443}`)
	recorder := httptest.NewRecorder()
	h.HandleClearStreamPort(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("clear stream status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if _, err := os.Stat(streamFile); err != nil {
		t.Fatalf("reuse mode touched external stream config: %v", err)
	}
}

func TestServiceControlRequestCanOnlyTightenNginxOwnership(t *testing.T) {
	h := NewManageHandler("test-token", "auto", "")

	req := authenticatedRequest(t, http.MethodPost, "/", `{"service":"nginx","action":"restart","nginx_mode":"reuse_existing"}`)
	recorder := httptest.NewRecorder()
	h.HandleServiceControl(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("reuse request status = %d, want %d: %s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	if h.currentNginxMode() != constants.NginxModeReuseExisting {
		t.Fatalf("reuse request did not tighten runtime mode: %q", h.currentNginxMode())
	}

	req = authenticatedRequest(t, http.MethodPost, "/", `{"service":"nginx","action":"restart","nginx_mode":"managed"}`)
	recorder = httptest.NewRecorder()
	h.HandleServiceControl(recorder, req)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("managed request downgraded protected runtime: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if h.currentNginxMode() != constants.NginxModeReuseExisting {
		t.Fatalf("managed request downgraded runtime mode: %q", h.currentNginxMode())
	}
}

func TestNginxServersListIncludesReuseOwnedDomainConfigs(t *testing.T) {
	root := t.TempDir()
	mainConfig := filepath.Join(root, "nginx.conf")
	if err := os.WriteFile(mainConfig, []byte("events {}\nhttp {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	serversDir := filepath.Join(nginxReusePrivateRoot(mainConfig), "servers")
	if err := os.MkdirAll(serversDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(serversDir, "reuse.example.com.conf"), []byte(arcwayReuseConfigMarker+"\nserver {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	originalFind := findNginxForReuse
	originalRun := runNginxForReuse
	findNginxForReuse = func() string { return "fake-nginx" }
	runNginxForReuse = func(_ string, args ...string) (string, error) {
		if len(args) == 1 && args[0] == "-V" {
			return "nginx version: fake --prefix=" + root + " --conf-path=" + mainConfig, nil
		}
		return "", fmt.Errorf("unexpected nginx args: %v", args)
	}
	t.Cleanup(func() {
		findNginxForReuse = originalFind
		runNginxForReuse = originalRun
	})

	h := NewManageHandler("test-token", "auto", "")
	req := authenticatedRequest(t, http.MethodGet, "/", "")
	recorder := httptest.NewRecorder()
	h.HandleNginxServersList(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("servers list status = %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "reuse.example.com") {
		t.Fatalf("reuse-owned domain was not listed: %s", recorder.Body.String())
	}
}

func authenticatedRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
	req.Header.Set(constants.HeaderAuthorization, constants.BearerPrefix+"test-token")
	return req
}
