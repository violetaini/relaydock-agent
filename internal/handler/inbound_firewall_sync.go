package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
)

const (
	arcwayFirewallHelperPath      = "/usr/local/sbin/arcway-agent-firewall"
	arcwayFirewallEnvironmentPath = "/etc/arcway-port-firewall.env"
)

type configFileSnapshot struct {
	existed bool
	content []byte
	mode    os.FileMode
}

func captureConfigFile(path string) (configFileSnapshot, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return configFileSnapshot{}, nil
	}
	if err != nil {
		return configFileSnapshot{}, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return configFileSnapshot{}, err
	}
	return configFileSnapshot{existed: true, content: content, mode: info.Mode().Perm()}, nil
}

func restoreConfigFile(path string, snapshot configFileSnapshot) error {
	if !snapshot.existed {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		} else if err == nil {
			return syncInboundMutationFenceParent(path)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeFileAtomicDurable(path, snapshot.content, snapshot.mode)
}

func writeXrayConfigAtomic(path string, content []byte) error {
	mode := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeFileAtomicDurable(path, content, mode)
}

func writeFileAtomicDurable(path string, content []byte, mode os.FileMode) (returnErr error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".arcway-xray-rollback-*.json")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	closed := false
	defer func() { _ = os.Remove(tempPath) }()
	defer func() {
		if !closed {
			if closeErr := file.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncInboundMutationFenceParent(path)
}

func syncArcwayInboundFirewall(ctx context.Context) error {
	return syncArcwayInboundFirewallPaths(ctx, arcwayFirewallHelperPath, arcwayFirewallEnvironmentPath)
}

func syncArcwayInboundFirewallPaths(ctx context.Context, helperPath, environmentPath string) error {
	info, err := os.Stat(helperPath)
	if errors.Is(err, os.ErrNotExist) {
		if _, envErr := os.Stat(environmentPath); envErr == nil {
			return fmt.Errorf("Arcway firewall helper is missing; rerun the node installation")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Arcway firewall helper: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return fmt.Errorf("Arcway firewall helper is not executable")
	}
	helper, err := os.ReadFile(helperPath)
	if err != nil {
		return fmt.Errorf("read Arcway firewall helper: %w", err)
	}
	if !bytes.Contains(helper, []byte("PUBLIC_RULES_RAW=")) || !bytes.Contains(helper, []byte("-arcway-firewall-rules=")) {
		return fmt.Errorf("Arcway firewall helper is outdated; rerun the node installation before changing inbounds")
	}
	command := exec.CommandContext(ctx, helperPath)
	output, err := command.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return fmt.Errorf("reconcile Arcway inbound firewall: %s", message)
	}
	return nil
}

func (h *ManageHandler) reconcileInboundFirewall() error {
	if h.inboundFirewallSync == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return h.inboundFirewallSync(ctx)
}

func inboundFromSnapshot(snapshot configFileSnapshot, tag string) (map[string]interface{}, error) {
	if !snapshot.existed {
		return nil, nil
	}
	var config map[string]interface{}
	if err := json.Unmarshal(snapshot.content, &config); err != nil {
		return nil, fmt.Errorf("parse prior Xray config: %w", err)
	}
	inbounds, _ := config["inbounds"].([]interface{})
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]interface{})
		if inboundTag, _ := inbound["tag"].(string); inboundTag == tag {
			return inbound, nil
		}
	}
	return nil, nil
}

func (h *ManageHandler) rollbackExternalInboundMutation(
	configPath string,
	snapshot configFileSnapshot,
	tag string,
	original map[string]interface{},
	handlerClient command.HandlerServiceClient,
) error {
	var failures []string
	configRestored := false
	if err := restoreConfigFile(configPath, snapshot); err != nil {
		failures = append(failures, "config: "+err.Error())
	} else {
		configRestored = true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var runtimeErr error
	if original != nil {
		runtimeErr = h.addInbound(ctx, handlerClient, original)
	} else {
		runtimeErr = h.removeInbound(ctx, handlerClient, tag)
	}
	if runtimeErr != nil && !isMissingInboundError(runtimeErr) {
		failures = append(failures, "runtime: "+runtimeErr.Error())
	}
	if configRestored {
		if err := h.reconcileInboundFirewall(); err != nil {
			failures = append(failures, "firewall: "+err.Error())
		}
	}
	if len(failures) != 0 {
		return fmt.Errorf("rollback failures: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (h *ManageHandler) rollbackEmbeddedInboundMutation(
	configPath string,
	snapshot configFileSnapshot,
	tag string,
	original map[string]interface{},
) error {
	var failures []string
	configRestored := false
	if err := restoreConfigFile(configPath, snapshot); err != nil {
		failures = append(failures, "config: "+err.Error())
	} else {
		configRestored = true
	}
	if original != nil {
		if err := h.replaceRuntimeInbound(context.Background(), tag, original); err != nil {
			failures = append(failures, "runtime: "+err.Error())
		}
	} else if err := h.embeddedXray.RemoveInbound(tag); err != nil && !isMissingInboundError(err) {
		failures = append(failures, "runtime: "+err.Error())
	}
	if configRestored {
		if err := h.reconcileInboundFirewall(); err != nil {
			failures = append(failures, "firewall: "+err.Error())
		}
	}
	if len(failures) != 0 {
		return fmt.Errorf("rollback failures: %s", strings.Join(failures, "; "))
	}
	return nil
}

func isMissingInboundError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "not enough information") ||
		strings.Contains(message, "not found") ||
		strings.Contains(message, "no such")
}
