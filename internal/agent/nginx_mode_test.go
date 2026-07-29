package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/config"
	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestConfigUpdatePersistsNginxModeAndUpdatesHook(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("token: test\nnginx_mode: managed\n"), 0600); err != nil {
		t.Fatal(err)
	}

	client := NewClient(&config.Config{NginxMode: constants.NginxModeManaged})
	client.SetConfigPath(configPath)
	var hookMode string
	client.SetNginxModeHook(func(mode string) { hookMode = mode })
	client.handleConfigUpdate(map[string]string{"nginx_mode": constants.NginxModeReuseExisting})

	if client.config.NginxMode != constants.NginxModeReuseExisting {
		t.Fatalf("client nginx mode = %q", client.config.NginxMode)
	}
	if hookMode != constants.NginxModeReuseExisting {
		t.Fatalf("hook mode = %q", hookMode)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "nginx_mode: reuse_existing") {
		t.Fatalf("nginx mode was not persisted: %q", data)
	}
}

func TestConfigUpdateRejectsInvalidNginxMode(t *testing.T) {
	client := NewClient(&config.Config{NginxMode: constants.NginxModeManaged})
	called := false
	client.SetNginxModeHook(func(string) { called = true })
	client.handleConfigUpdate(map[string]string{"nginx_mode": "unmanaged"})

	if client.config.NginxMode != constants.NginxModeManaged || called {
		t.Fatalf("invalid nginx mode changed runtime state: mode=%q hook=%v", client.config.NginxMode, called)
	}
}
