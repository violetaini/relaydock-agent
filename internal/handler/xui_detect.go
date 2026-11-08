package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type XUIDetectionResult struct {
	Installed    bool      `json:"installed"`
	Running      bool      `json:"running"`
	DBPath       string    `json:"db_path,omitempty"`
	BinaryPath   string    `json:"binary_path,omitempty"`
	ServiceUnit  string    `json:"service_unit,omitempty"`
	InboundCount int       `json:"inbound_count"`
	ClientCount  int       `json:"client_count"`
	ActivePorts  []int     `json:"active_ports"`
	DetectedAt   time.Time `json:"detected_at"`
	IsCoexisting bool      `json:"is_coexisting"`
	Message      string    `json:"message"`
}

// HandleXUIDetect performs a 100% read-only inspection of 3x-ui on the host node.
// Under no circumstances does this function stop, modify, or signal any running 3x-ui processes.
func (h *ManageHandler) HandleXUIDetect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !h.authenticate(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	result := XUIDetectionResult{
		DetectedAt:  time.Now(),
		ActivePorts: make([]int, 0),
	}

	// 1. Check binary existence
	binaryCandidates := []string{
		"/usr/local/x-ui/x-ui",
		"/usr/bin/x-ui",
		"/usr/local/bin/x-ui",
	}
	for _, p := range binaryCandidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			result.Installed = true
			result.BinaryPath = p
			break
		}
	}

	// 2. Check service status via systemctl (non-blocking, timeout 2s)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "x-ui")
	out, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		result.Running = true
		result.Installed = true
		result.ServiceUnit = "x-ui.service"
	} else {
		// Check if unit file exists
		checkUnitCmd := exec.CommandContext(ctx, "systemctl", "status", "x-ui")
		if statusOut, _ := checkUnitCmd.Output(); len(statusOut) > 0 {
			result.ServiceUnit = "x-ui.service"
			if strings.Contains(string(statusOut), "active (running)") {
				result.Running = true
				result.Installed = true
			}
		}
	}

	// 3. Check database existence
	dbCandidates := []string{
		"/etc/x-ui/x-ui.db",
		"/usr/local/x-ui/bin/x-ui.db",
		"/root/x-ui/x-ui.db",
	}
	for _, p := range dbCandidates {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			result.Installed = true
			result.DBPath = p
			break
		}
	}

	// 4. Read generated Xray configuration safely if present
	configCandidates := []string{
		"/usr/local/x-ui/bin/config.json",
		"/etc/x-ui/config.json",
	}

	for _, cfgPath := range configCandidates {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			continue
		}

		var cfg struct {
			Inbounds []struct {
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
				Tag      string `json:"tag"`
				Settings struct {
					Clients []interface{} `json:"clients"`
				} `json:"settings"`
			} `json:"inbounds"`
		}

		if err := json.Unmarshal(data, &cfg); err == nil {
			result.InboundCount = len(cfg.Inbounds)
			clientTotal := 0
			portSet := make(map[int]bool)
			for _, ib := range cfg.Inbounds {
				if ib.Port > 0 {
					portSet[ib.Port] = true
				}
				clientTotal += len(ib.Settings.Clients)
			}
			for p := range portSet {
				result.ActivePorts = append(result.ActivePorts, p)
			}
			result.ClientCount = clientTotal
			break
		}
	}

	// 5. Evaluate coexistence
	if result.Running {
		result.IsCoexisting = true
		result.Message = fmt.Sprintf("3x-ui 正在运行中 (平稳共存模式: %d 个入站, %d 个用户, %d 个活跃端口)",
			result.InboundCount, result.ClientCount, len(result.ActivePorts))
	} else if result.Installed {
		result.Message = "已检测到 3x-ui 安装文件或数据库，但服务未启动"
	} else {
		result.Message = "未在此节点检测到 3x-ui 安装"
	}

	writeJSON(w, http.StatusOK, result)
}
