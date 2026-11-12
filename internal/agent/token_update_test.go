package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/violetaini/relaydock-agent/internal/config"
)

func TestHandleTokenUpdatePersistsConfigToken(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("master_url: \"https://example.com\"\ntoken: \"old-token\"\nxray_mode: external\n"), 0600); err != nil {
		t.Fatal(err)
	}

	client := NewClient(&config.Config{Token: "old-token"})
	client.SetConfigPath(configPath)

	client.handleTokenUpdate(WSTokenUpdatePayload{
		ServerToken: "new-rotated-token-123",
		ExpiresAt:   time.Now().Add(7 * 24 * time.Hour),
	})

	if client.config.Token != "new-rotated-token-123" {
		t.Fatalf("client.config.Token = %q, want %q", client.config.Token, "new-rotated-token-123")
	}

	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if reloaded.Token != "new-rotated-token-123" {
		t.Fatalf("reloaded.Token = %q, want %q", reloaded.Token, "new-rotated-token-123")
	}
}

func TestHandleTokenUpdateIgnoresEmptyToken(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("token: \"old-token\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	client := NewClient(&config.Config{Token: "old-token"})
	client.SetConfigPath(configPath)

	client.handleTokenUpdate(WSTokenUpdatePayload{
		ServerToken: "   ",
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	if client.config.Token != "old-token" {
		t.Fatalf("client.config.Token = %q, want unchanged %q", client.config.Token, "old-token")
	}

	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if reloaded.Token != "old-token" {
		t.Fatalf("reloaded.Token = %q, want unchanged %q", reloaded.Token, "old-token")
	}
}
