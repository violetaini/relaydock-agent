// warp_handler.go — WARP 出站管理 RPC handler。
// 4 个 endpoint(install/status/license/remove)挂在 /api/child/warp/*,通过 master ws_rpc 调。
//
// install/license 流程:
//   1. 调 warp.Service 完成 Cloudflare API 注册 / 刷新 / 升级
//   2. 用 BuildOutbounds() 生成 warp-v4 + warp-v6 双 outbound map
//   3. 复用 ManageHandler.addOutbound + persistOutbound 注入到本机 xray runtime + 持久化到 config

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/violetaini/relaydock-agent/internal/constants"
	"github.com/violetaini/relaydock-agent/internal/warp"
	"github.com/violetaini/relaydock-agent/internal/xrpc"
)

// WarpHandler 持有 warp service + 一个回调用于复用 ManageHandler 的 outbound 管理能力。
type WarpHandler struct {
	configToken string
	service     *warp.Service
	manage      *ManageHandler // 复用 addOutbound / removeOutbound / persistOutbound / findXrayAPIPort
}

// NewWarpHandler 在 main.go 里构造,传入 token + warp service + manage handler。
func NewWarpHandler(configToken string, svc *warp.Service, manage *ManageHandler) *WarpHandler {
	return &WarpHandler{configToken: configToken, service: svc, manage: manage}
}

// Service 暴露内部 service,供 agent client 在 heartbeat 时查状态上报。
func (h *WarpHandler) Service() *warp.Service {
	return h.service
}

// --- HTTP handlers ---

// HandleInstall POST /api/child/warp/install
// 幂等:已注册 → 直接刷新 outbound + 返回 status;未注册 → 注册 + 注入 outbound。
func (h *WarpHandler) HandleInstall(w http.ResponseWriter, r *http.Request) {
	if !h.auth(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	st, err := h.service.EnsureRegistered(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("WARP register failed: %v", err))
		return
	}
	if err := h.applyOutbounds(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Apply WARP outbounds failed: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, h.statusResponse(st))
}

// HandleStatus GET /api/child/warp/status
func (h *WarpHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if !h.auth(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	writeJSON(w, http.StatusOK, h.statusResponse(h.service.State()))
}

// HandleLicense POST /api/child/warp/license  body: {"license":"..."}
// 升级 WARP+ 后必须重建 outbound(Cloudflare 会换 peer / addresses)。
func (h *WarpHandler) HandleLicense(w http.ResponseWriter, r *http.Request) {
	if !h.auth(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var req struct {
		License string `json:"license"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.License == "" {
		writeError(w, http.StatusBadRequest, "license is required")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	st, err := h.service.SetLicense(ctx, req.License)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("WARP set license failed: %v", err))
		return
	}
	// peer 可能变了,重建 outbound
	if err := h.applyOutbounds(ctx); err != nil {
		log.Printf("[WARP] license updated but apply outbounds failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success":           false,
			"partial":           true,
			"license_updated":   true,
			"outbounds_applied": false,
			"status":            h.statusResponse(st),
			"error":             fmt.Sprintf("WARP license updated, but applying outbounds failed: %v", err),
		})
		return
	}
	writeJSON(w, http.StatusOK, h.statusResponse(st))
}

// HandleRemove POST /api/child/warp/remove
// Cloudflare 注销 + 本地状态清空 + xray 中删 warp-v4 / warp-v6 outbound。
func (h *WarpHandler) HandleRemove(w http.ResponseWriter, r *http.Request) {
	if !h.auth(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Keep warp.json as the retry marker until both runtime/persisted outbounds
	// and the Cloudflare device have been removed. Otherwise a partial outbound
	// failure followed by a successful Cloudflare delete becomes unrecoverable.
	outboundResult, removalErr := removeWarpInRetryableOrder(
		func() (warpOutboundRemovalResult, error) {
			return h.removeOutboundTags(ctx, "warp-v4", "warp-v6")
		},
		func() error {
			return h.service.Uninstall(ctx)
		},
	)
	if removalErr != nil {
		log.Printf("[WARP] removal incomplete; retry state retained: %v", removalErr)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success":     false,
			"partial":     true,
			"uninstalled": h.service.State() == nil,
			"outbounds":   outboundResult,
			"error":       fmt.Sprintf("WARP removal incomplete; retry required: %v", removalErr),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":     true,
		"uninstalled": true,
		"outbounds":   outboundResult,
	})
}

// --- 内部 helpers ---

// applyOutbounds 用当前 state 构造 warp-v4 + warp-v6,先尝试 remove 老的(若存在),再 add 新的 + 持久化。
// xray runtime AddOutbound 在 tag 已存在时报错,所以必须先 remove(idempotent — 不存在 remove 也不抛致命错)。
func (h *WarpHandler) applyOutbounds(ctx context.Context) error {
	outbounds, err := h.service.BuildOutbounds()
	if err != nil {
		return err
	}
	apiPort := h.manage.findXrayAPIPort()
	if apiPort == 0 {
		return fmt.Errorf("xray API not available")
	}
	clients, err := xrpc.New(ctx, constants.LocalhostIP, uint16(apiPort))
	if err != nil {
		return fmt.Errorf("connect xray gRPC: %w", err)
	}
	defer clients.Connection.Close()

	for _, ob := range outbounds {
		tag, _ := ob["tag"].(string)
		// 已存在则先 remove(忽略错误 — 不存在也 OK)
		_ = h.manage.removeOutbound(ctx, clients.Handler, tag)
		if err := h.manage.addOutbound(ctx, clients.Handler, ob); err != nil {
			return fmt.Errorf("add outbound %s: %w", tag, err)
		}
		if err := h.manage.persistOutbound(ob); err != nil {
			return fmt.Errorf("persist outbound %s to config: %w", tag, err)
		}
	}
	return nil
}

type warpOutboundRemovalResult struct {
	RuntimeAttempted bool `json:"runtime_attempted"`
	RuntimeRemoved   bool `json:"runtime_removed"`
	ConfigAttempted  bool `json:"config_attempted"`
	ConfigRemoved    bool `json:"config_removed"`
}

func removeWarpInRetryableOrder(
	removeOutbounds func() (warpOutboundRemovalResult, error),
	uninstall func() error,
) (warpOutboundRemovalResult, error) {
	result, err := removeOutbounds()
	if err != nil {
		return result, fmt.Errorf("remove WARP outbounds: %w", err)
	}
	if err := uninstall(); err != nil {
		return result, err
	}
	return result, nil
}

// removeWarpOutboundTags 把运行时和配置文件删除当作两条独立路径，一条失败不会阻断另一条。
// callback 为 nil 表示该路径无法尝试，具体的 setup 错误由 caller 合并返回。
func removeWarpOutboundTags(tags []string, runtimeRemove, configRemove func(string) error) (warpOutboundRemovalResult, error) {
	result := warpOutboundRemovalResult{
		RuntimeAttempted: runtimeRemove != nil,
		RuntimeRemoved:   runtimeRemove != nil,
		ConfigAttempted:  configRemove != nil,
		ConfigRemoved:    configRemove != nil,
	}
	var failures []error
	for _, tag := range tags {
		if runtimeRemove != nil {
			if err := runtimeRemove(tag); err != nil {
				result.RuntimeRemoved = false
				failures = append(failures, fmt.Errorf("remove runtime outbound %s: %w", tag, err))
			}
		}
		if configRemove != nil {
			if err := configRemove(tag); err != nil {
				result.ConfigRemoved = false
				failures = append(failures, fmt.Errorf("remove config outbound %s: %w", tag, err))
			}
		}
	}
	return result, errors.Join(failures...)
}

// removeOutboundTags 从 xray runtime 和 config 文件里删除指定 tags 的 outbound。
func (h *WarpHandler) removeOutboundTags(ctx context.Context, tags ...string) (warpOutboundRemovalResult, error) {
	var (
		clients       *xrpc.Clients
		runtimeRemove func(string) error
		setupErr      error
	)
	apiPort := h.manage.findXrayAPIPort()
	if apiPort == 0 {
		setupErr = fmt.Errorf("xray runtime removal unavailable: xray API not available")
	} else {
		var err error
		clients, err = xrpc.New(ctx, constants.LocalhostIP, uint16(apiPort))
		if err != nil {
			setupErr = fmt.Errorf("xray runtime removal unavailable: connect xray gRPC: %w", err)
		} else {
			defer clients.Connection.Close()
			runtimeRemove = func(tag string) error {
				err := h.manage.removeOutbound(ctx, clients.Handler, tag)
				if err != nil && isMissingInboundError(err) {
					return nil
				}
				return err
			}
		}
	}
	result, removeErr := removeWarpOutboundTags(tags, runtimeRemove, h.manage.removeOutboundFromConfig)
	if setupErr != nil {
		result.RuntimeAttempted = false
		result.RuntimeRemoved = false
	}
	return result, errors.Join(setupErr, removeErr)
}

// statusResponse 把 State 转成给 master 看的状态 dto。state 为 nil 时返回 installed=false。
func (h *WarpHandler) statusResponse(st *warp.State) map[string]any {
	if st == nil || st.DeviceID == "" {
		return map[string]any{"success": true, "installed": false}
	}
	return map[string]any{
		"success":        true,
		"installed":      true,
		"license_active": st.LicenseKey != "",
		"device_id":      st.DeviceID,
		"addr_v4":        st.AddrV4,
		"addr_v6":        st.AddrV6,
		"registered_at":  st.RegisteredAt,
	}
}

func (h *WarpHandler) auth(r *http.Request) bool {
	// WS RPC requests are built in memory by the authenticated dispatcher. An
	// external caller can forge the header, so the synthetic RemoteAddr marker
	// is required as well.
	if r.Header.Get("X-WS-RPC") == "1" && r.RemoteAddr == "ws-rpc" {
		return true
	}
	if !constants.IsAgentUserAgent(r.Header.Get(constants.HeaderUserAgent)) {
		return false
	}
	if h.configToken == "" {
		return true
	}
	token := r.Header.Get(constants.HeaderAuthorization)
	const prefix = "Bearer "
	if len(token) > len(prefix) && token[:len(prefix)] == prefix {
		return token[len(prefix):] == h.configToken
	}
	return false
}

// 必须导出 paths,方便 cmd/main.go 注册路由,避免再去引 internal/constants。
var (
	_ = constants.PathChildWarpInstall
	_ = constants.PathChildWarpStatus
	_ = constants.PathChildWarpLicense
	_ = constants.PathChildWarpRemove
)
