package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"mmw-agent/internal/constants"
)

// HandleSwitchNginxMode persists the ownership boundary before acknowledging
// the control plane. This gives the panel a request/reply operation instead of
// relying on the fire-and-forget config_update message.
func (h *ManageHandler) HandleSwitchNginxMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !h.authenticate(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var req struct {
		NginxMode string `json:"nginx_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.NginxMode != constants.NginxModeManaged && req.NginxMode != constants.NginxModeReuseExisting {
		writeError(w, http.StatusBadRequest, "nginx_mode must be 'managed' or 'reuse_existing'")
		return
	}
	if h.configPath == "" {
		writeError(w, http.StatusInternalServerError, "Config path not set")
		return
	}
	if err := persistAgentConfigValue(h.configPath, "nginx_mode", req.NginxMode); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Persist nginx_mode: %v", err))
		return
	}

	h.SetNginxMode(req.NginxMode)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"nginx_mode": req.NginxMode,
	})
}

func persistAgentConfigValue(path, key, value string) (returnErr error) {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key+":") {
			lines[i] = key + ": " + value
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, key+": "+value)
	}

	temp, err := os.CreateTemp(filepath.Dir(path), ".arcway-agent-config-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if returnErr != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := temp.WriteString(strings.Join(lines, "\n")); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}
