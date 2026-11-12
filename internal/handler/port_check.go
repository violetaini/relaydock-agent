package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

type portCheckResponse struct {
	Success    bool   `json:"success"`
	Port       int    `json:"port"`
	Available  bool   `json:"available"`
	OccupiedBy string `json:"occupied_by,omitempty"`
	Network    string `json:"network,omitempty"`
	Tag        string `json:"tag,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// HandleCheckPort handles GET /api/child/ports/check to verify whether a port
// is free in Xray config, agent reserved ports, and active OS sockets.
func (h *ManageHandler) HandleCheckPort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !h.authenticate(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	portText := strings.TrimSpace(r.URL.Query().Get("port"))
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		writeError(w, http.StatusBadRequest, "port must be an integer between 1 and 65535")
		return
	}

	networks, err := parseRequestedPortNetworks(r.URL.Query().Get("network"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ignoreTag := strings.TrimSpace(r.URL.Query().Get("ignore_tag"))
	networkSummary := strings.Join(networks, ",")

	if h.listenPort > 0 && port == h.listenPort && containsString(networks, "tcp") {
		writeJSON(w, http.StatusOK, portCheckResponse{
			Success:    true,
			Port:       port,
			Available:  false,
			OccupiedBy: "agent_port",
			Network:    "tcp",
			Reason:     fmt.Sprintf("端口 %d 为 RelayDock Agent 监听端口", port),
		})
		return
	}

	h.inboundsMu.Lock()
	var configInbounds []map[string]interface{}
	if h.inboundMutationConfigPathResolver != nil {
		if resolvedPath := strings.TrimSpace(h.inboundMutationConfigPathResolver()); resolvedPath != "" {
			configInbounds = readInboundsFromJSONFile(resolvedPath)
		}
	}
	if configInbounds == nil {
		configInbounds = h.getInboundsFromConfig()
	}
	h.inboundsMu.Unlock()

	ignoredNets := map[string]bool{}
	for _, ib := range configInbounds {
		tag, _ := ib["tag"].(string)
		tag = strings.TrimSpace(tag)
		if ignoreTag != "" && tag == ignoreTag {
			if inboundMatchesPort(ib["port"], port) {
				for _, netName := range inboundConfigNetworks(ib) {
					ignoredNets[netName] = true
				}
			}
			continue
		}
		if !inboundMatchesPort(ib["port"], port) {
			continue
		}
		existingNets := inboundConfigNetworks(ib)
		conflictNet := firstIntersectingNetwork(networks, existingNets)
		if conflictNet == "" {
			continue
		}
		protocol, _ := ib["protocol"].(string)
		label := tag
		if label == "" {
			label = "未命名入站"
		}
		if protocol != "" {
			label += " (" + protocol + ")"
		}
		writeJSON(w, http.StatusOK, portCheckResponse{
			Success:    true,
			Port:       port,
			Available:  false,
			OccupiedBy: "xray_inbound",
			Network:    conflictNet,
			Tag:        tag,
			Protocol:   protocol,
			Reason:     fmt.Sprintf("端口 %d 已被 Xray 入站 %s 占用", port, label),
		})
		return
	}

	probeNetworks := networks
	if len(ignoredNets) > 0 && h.isXrayCurrentlyRunning() {
		filtered := make([]string, 0, len(networks))
		for _, netName := range networks {
			if !ignoredNets[netName] {
				filtered = append(filtered, netName)
			}
		}
		probeNetworks = filtered
	}

	if len(probeNetworks) > 0 {
		probe := h.portAvailabilityProbe
		if probe == nil {
			probe = probeHostPortsAvailable
		}
		if ok, conflictNet, reason := probe(port, probeNetworks); !ok {
			writeJSON(w, http.StatusOK, portCheckResponse{
				Success:    true,
				Port:       port,
				Available:  false,
				OccupiedBy: "system_listener",
				Network:    conflictNet,
				Reason:     reason,
			})
			return
		}
	}

	writeJSON(w, http.StatusOK, portCheckResponse{
		Success:   true,
		Port:      port,
		Available: true,
		Network:   networkSummary,
	})
}

func (h *ManageHandler) isXrayCurrentlyRunning() bool {
	if h.xrayRunningProbe != nil {
		return h.xrayRunningProbe()
	}
	st := h.getXrayStatus()
	return st != nil && st.Running
}

func parseRequestedPortNetworks(raw string) ([]string, error) {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	if trimmed == "" {
		return []string{"tcp", "udp"}, nil
	}
	trimmed = strings.ReplaceAll(trimmed, "+", ",")
	trimmed = strings.ReplaceAll(trimmed, "_", ",")
	seen := map[string]bool{}
	out := make([]string, 0, 2)
	for _, part := range strings.Split(trimmed, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if p != "tcp" && p != "udp" {
			return nil, fmt.Errorf("unsupported network %q", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"tcp", "udp"}, nil
	}
	return out, nil
}

func inboundMatchesPort(raw interface{}, target int) bool {
	switch v := raw.(type) {
	case float64:
		return int(v) == target
	case int:
		return v == target
	case json.Number:
		parsed, err := v.Int64()
		return err == nil && int(parsed) == target
	case string:
		for _, segment := range strings.Split(strings.TrimSpace(v), ",") {
			seg := strings.TrimSpace(segment)
			if seg == "" {
				continue
			}
			if lo, hi, ok := strings.Cut(seg, "-"); ok {
				start, err1 := strconv.Atoi(strings.TrimSpace(lo))
				end, err2 := strconv.Atoi(strings.TrimSpace(hi))
				if err1 == nil && err2 == nil && target >= start && target <= end {
					return true
				}
				continue
			}
			if p, err := strconv.Atoi(seg); err == nil && p == target {
				return true
			}
		}
	}
	return false
}

func inboundConfigNetworks(inbound map[string]interface{}) []string {
	protocol, _ := inbound["protocol"].(string)
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "hysteria", "hysteria2", "wireguard":
		return []string{"udp"}
	case "chitanda":
		return []string{"tcp", "udp"}
	case "dokodemo-door", "tunnel":
		if settings, ok := inbound["settings"].(map[string]interface{}); ok {
			if rawNet, ok := settings["network"].(string); ok {
				if parsed, err := parseRequestedPortNetworks(rawNet); err == nil {
					return parsed
				}
			}
		}
		return []string{"tcp", "udp"}
	case "shadowsocks":
		if settings, ok := inbound["settings"].(map[string]interface{}); ok {
			if rawNet, ok := settings["network"].(string); ok {
				if parsed, err := parseRequestedPortNetworks(rawNet); err == nil {
					return parsed
				}
			}
		}
		return []string{"tcp", "udp"}
	case "vless", "vmess", "trojan", "socks", "http", "anytls", "mieru":
		return []string{"tcp"}
	default:
		return []string{"tcp", "udp"}
	}
}

func firstIntersectingNetwork(a, b []string) string {
	for _, x := range a {
		if containsString(b, x) {
			return x
		}
	}
	return ""
}

func containsString(slice []string, target string) bool {
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}

func probeHostPortsAvailable(port int, networks []string) (bool, string, string) {
	for _, netName := range networks {
		switch netName {
		case "tcp":
			if ok, detail := probeTCPAvailable(port); !ok {
				return false, "tcp", fmt.Sprintf("端口 %d 已被本机 TCP 进程占用 (%s)", port, detail)
			}
		case "udp":
			if ok, detail := probeUDPAvailable(port); !ok {
				return false, "udp", fmt.Sprintf("端口 %d 已被本机 UDP 进程占用 (%s)", port, detail)
			}
		}
	}
	return true, "", ""
}

func probeTCPAvailable(port int) (bool, string) {
	for _, candidate := range []struct {
		network string
		addr    string
	}{
		{network: "tcp4", addr: fmt.Sprintf("0.0.0.0:%d", port)},
		{network: "tcp6", addr: fmt.Sprintf("[::]:%d", port)},
	} {
		ln, err := net.Listen(candidate.network, candidate.addr)
		if err == nil {
			_ = ln.Close()
			continue
		}
		if candidate.network == "tcp6" && isUnsupportedAddressFamilyErr(err) {
			continue
		}
		return false, candidate.addr
	}
	return true, ""
}

func probeUDPAvailable(port int) (bool, string) {
	for _, candidate := range []struct {
		network string
		addr    string
	}{
		{network: "udp4", addr: fmt.Sprintf("0.0.0.0:%d", port)},
		{network: "udp6", addr: fmt.Sprintf("[::]:%d", port)},
	} {
		pc, err := net.ListenPacket(candidate.network, candidate.addr)
		if err == nil {
			_ = pc.Close()
			continue
		}
		if candidate.network == "udp6" && isUnsupportedAddressFamilyErr(err) {
			continue
		}
		return false, candidate.addr
	}
	return true, ""
}

func isUnsupportedAddressFamilyErr(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT)
}

var _ = constants.PathChildPortsCheck
