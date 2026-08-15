package embedded

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	officialstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	confserial "github.com/xtls/xray-core/infra/conf/serial"

	officialdispatcher "github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/app/metrics"
	"github.com/xtls/xray-core/app/policy"

	mydispatcher "github.com/violetaini/relaydock-agent/internal/dispatcher"
	"github.com/violetaini/relaydock-agent/internal/limiter"
)

// ValidateConfigProtocols enforces protocols intentionally disabled by the
// Agent product surface before either the embedded parser or an external Xray
// binary sees the configuration.
func ValidateConfigProtocols(jsonData []byte) error {
	var value any
	if err := json.Unmarshal(jsonData, &value); err != nil {
		return err
	}
	return rejectDisabledProtocol(value, "config")
}

func rejectDisabledProtocol(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "." + key
			if key == "protocol" {
				if protocol, ok := child.(string); ok && strings.EqualFold(strings.TrimSpace(protocol), "snell") {
					return fmt.Errorf("%s: protocol %q is disabled", childPath, protocol)
				}
			}
			if err := rejectDisabledProtocol(child, childPath); err != nil {
				return err
			}
		}
	case []any:
		for index, child := range typed {
			if err := rejectDisabledProtocol(child, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

// TestConfigJSON 用 xray-core 库语义验证一份 JSON 配置:
//   - 解析失败 → 返回 error,内容包含 xray-core 抛出的字段路径/类型错误
//   - 解析成功 → 返回 nil
//
// 不会绑定端口、不会和正在运行的内嵌 xray instance 冲突 — 只走 conf parsing。
// 实现等价 xray 二进制的 -test flag 内部所做的事(LoadConfig,不 Build instance)。
func TestConfigJSON(jsonData []byte) error {
	if err := ValidateConfigProtocols(jsonData); err != nil {
		return err
	}
	_, err := confserial.LoadJSONConfig(bytes.NewReader(jsonData))
	return err
}

// AccessLogPath 非空时,buildCoreConfig 会把内嵌 xray 的 access log 强制落到这个文件
// (覆盖下发配置里的 log.access)。由 main 按 agent 日志目录设置。
//
// 目的:内嵌模式下 access log 默认直写 stdout,面板「查看 xray 日志」查 journalctl -u xray
// (不存在的 unit)看不到。落文件后面板直接读它,不依赖 systemd。
var AccessLogPath string

// injectAccessLog 把 log.access 覆盖为 AccessLogPath。只动 access,不碰 loglevel ——
// access log(accepted/rejected)在 xray 里独立于 loglevel,用户设 error 也照打。
// 解析失败一律返回原始 data,绝不因为这个可选特性阻断 xray 启动。
func injectAccessLog(data []byte) []byte {
	if AccessLogPath == "" {
		return data
	}
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return data
	}
	logCfg, _ := m["log"].(map[string]any)
	if logCfg == nil {
		logCfg = map[string]any{}
		m["log"] = logCfg
	}
	logCfg["access"] = AccessLogPath
	out, err := json.Marshal(m)
	if err != nil {
		return data
	}
	return out
}

func buildCoreConfig(configPath string) (*core.Config, error) {
	return buildCoreConfigWithSuppressedInbounds(configPath, nil)
}

func buildCoreConfigWithSuppressedInbounds(configPath string, suppressed map[string]struct{}) (*core.Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	return buildCoreConfigJSONWithSuppressedInbounds(data, suppressed)
}

func buildCoreConfigJSONWithSuppressedInbounds(data []byte, suppressed map[string]struct{}) (*core.Config, error) {
	data, err := suppressConfiguredInbounds(data, suppressed)
	if err != nil {
		return nil, err
	}
	data = injectAccessLog(data)
	if err := ValidateConfigProtocols(data); err != nil {
		return nil, err
	}

	pbConfig, err := confserial.LoadJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	// 只注册自定义 dispatcher,不再注册 officialdispatcher。
	// 自定义 dispatcher.Type() 返回 routing.DispatcherType(),会被作为标准 routing.Dispatcher feature 解析,
	// 所有走 routing.Dispatcher 的流量进入自定义实现 → limiter / per-user RateWriter / user-traffic stats 才能挂得上。
	// 若同时注册官方 dispatcher,xray-core 内部会以官方实现为准,limiter 钩子完全无效。
	customApps := []*serial.TypedMessage{
		serial.ToTypedMessage(&mydispatcher.Config{}),
		serial.ToTypedMessage(&officialstats.Config{}),
		serial.ToTypedMessage(&policy.Config{
			Level: map[uint32]*policy.Policy{
				0: {
					Stats: &policy.Policy_Stats{
						UserUplink:   true,
						UserDownlink: true,
						UserOnline:   true,
					},
				},
			},
			System: &policy.SystemPolicy{
				Stats: &policy.SystemPolicy_Stats{
					InboundUplink:    true,
					InboundDownlink:  true,
					OutboundUplink:   true,
					OutboundDownlink: true,
				},
			},
		}),
	}

	// Remove existing dispatcher/stats/policy configs from parsed config
	// to avoid duplicates, then prepend ours.
	var filtered []*serial.TypedMessage
	skipTypes := map[string]bool{
		serial.GetMessageType(&officialdispatcher.Config{}): true,
		serial.GetMessageType(&officialstats.Config{}):      true,
		serial.GetMessageType(&policy.Config{}):             true,
		serial.GetMessageType(&mydispatcher.Config{}):       true,
		serial.GetMessageType(&metrics.Config{}):            true,
	}
	for _, app := range pbConfig.App {
		if !skipTypes[app.Type] {
			filtered = append(filtered, app)
		}
	}

	pbConfig.App = append(customApps, filtered...)

	return pbConfig, nil
}

// wireGuardInboundTagsMissingPersistentMappings finds WireGuard listeners that
// cannot be started with a complete source-to-user identity map. The caller
// suppresses these tags from its in-memory startup config while preserving the
// durable Xray file for later recovery.
func wireGuardInboundTagsMissingPersistentMappings(
	data []byte,
	snapshots []limiter.PersistentInboundSnapshot,
) (map[string]struct{}, error) {
	var config struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Settings struct {
				Peers []struct {
					AllowedIPs []string `json:"allowedIPs"`
				} `json:"peers"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config before WireGuard limiter validation: %w", err)
	}

	mappedByTag := make(map[string]map[string]struct{}, len(snapshots))
	for _, snapshot := range snapshots {
		tag := strings.TrimSpace(snapshot.InboundTag)
		if mappedByTag[tag] == nil {
			mappedByTag[tag] = make(map[string]struct{}, len(snapshot.WireGuardPeers))
		}
		for _, peer := range snapshot.WireGuardPeers {
			if address, ok := canonicalEmbeddedWireGuardHostPrefix(peer.Address); ok {
				mappedByTag[tag][address] = struct{}{}
			}
		}
	}

	missing := make(map[string]struct{})
	for _, inbound := range config.Inbounds {
		if !strings.EqualFold(strings.TrimSpace(inbound.Protocol), "wireguard") || len(inbound.Settings.Peers) == 0 {
			continue
		}
		tag := strings.TrimSpace(inbound.Tag)
		mapped := mappedByTag[tag]
		complete := len(mapped) > 0
		for _, peer := range inbound.Settings.Peers {
			if len(peer.AllowedIPs) == 0 {
				complete = false
				break
			}
			for _, allowedIP := range peer.AllowedIPs {
				address, ok := canonicalEmbeddedWireGuardHostPrefix(allowedIP)
				if !ok {
					complete = false
					break
				}
				if _, ok := mapped[address]; !ok {
					complete = false
					break
				}
			}
			if !complete {
				break
			}
		}
		if !complete {
			missing[tag] = struct{}{}
		}
	}
	return missing, nil
}

func canonicalEmbeddedWireGuardHostPrefix(value string) (string, bool) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || !prefix.IsValid() || prefix.Bits() != prefix.Addr().BitLen() {
		return "", false
	}
	return prefix.Addr().Unmap().String(), true
}

// suppressConfiguredInbounds removes selected inbound tags from an in-memory
// config copy before core construction. It deliberately leaves the on-disk
// configuration intact: authorization recovery restores only the runtime
// inbound and never has to rewrite a user's Xray configuration.
func suppressConfiguredInbounds(data []byte, suppressed map[string]struct{}) ([]byte, error) {
	if len(suppressed) == 0 {
		return data, nil
	}

	var config map[string]json.RawMessage
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config before inbound suppression: %w", err)
	}
	rawInbounds, ok := config["inbounds"]
	if !ok {
		return data, nil
	}

	var inbounds []json.RawMessage
	if err := json.Unmarshal(rawInbounds, &inbounds); err != nil {
		return nil, fmt.Errorf("parse config inbounds before suppression: %w", err)
	}

	filtered := make([]json.RawMessage, 0, len(inbounds))
	for _, inbound := range inbounds {
		var descriptor struct {
			Tag string `json:"tag"`
		}
		if err := json.Unmarshal(inbound, &descriptor); err != nil {
			return nil, fmt.Errorf("parse inbound before suppression: %w", err)
		}
		if _, blocked := suppressed[strings.TrimSpace(descriptor.Tag)]; blocked {
			continue
		}
		filtered = append(filtered, inbound)
	}

	encoded, err := json.Marshal(filtered)
	if err != nil {
		return nil, fmt.Errorf("encode filtered inbounds: %w", err)
	}
	config["inbounds"] = encoded
	data, err = json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("encode config after inbound suppression: %w", err)
	}
	return data, nil
}
