package embedded

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	feature_inbound "github.com/xtls/xray-core/features/inbound"
	feature_outbound "github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/stats"

	mydispatcher "github.com/violetaini/relaydock-agent/internal/dispatcher"
	"github.com/violetaini/relaydock-agent/internal/limiter"
)

type EmbeddedXray struct {
	configPath            string
	instance              *core.Instance
	dispatcher            *mydispatcher.Dispatcher
	statsManager          stats.Manager
	speedMonitor          *SpeedMonitor
	suppressedInboundTags map[string]struct{}
	mu                    sync.RWMutex
}

func New(configPath string) *EmbeddedXray {
	return &EmbeddedXray{
		configPath:   configPath,
		speedMonitor: NewSpeedMonitor(),
	}
}

func (e *EmbeddedXray) GetSpeedMonitor() *SpeedMonitor {
	return e.speedMonitor
}

// SetSuppressedInboundTags excludes the supplied inbound tags every time this
// embedded instance loads its durable configuration. The durable file is never
// rewritten: callers can later add an authorized inbound back through Xray's
// runtime API without losing its definition.
//
// ManageHandler updates this immediately before a start or restart while it
// holds its inbound lifecycle lock, so Start observes a stable authorization
// decision and never briefly binds a suspended RelayDock-owned listener.
func (e *EmbeddedXray) SetSuppressedInboundTags(tags []string) {
	filtered := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag != "" {
			filtered[tag] = struct{}{}
		}
	}

	e.mu.Lock()
	if len(filtered) == 0 {
		e.suppressedInboundTags = nil
	} else {
		e.suppressedInboundTags = filtered
	}
	e.mu.Unlock()
}

func (e *EmbeddedXray) suppressedInboundTagsSnapshot() map[string]struct{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.suppressedInboundTags) == 0 {
		return nil
	}
	tags := make(map[string]struct{}, len(e.suppressedInboundTags))
	for tag := range e.suppressedInboundTags {
		tags[tag] = struct{}{}
	}
	return tags
}

func (e *EmbeddedXray) Start() (retErr error) {
	// xray-core 内部偶发 panic(端口冲突 / 配置异常等)。没有 recover 时整个 agent 进程被带崩,
	// 主控看到 "connection reset by peer";加 recover 后返回 error,handler 正常回 500。
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("xray start panicked: %v", r)
		}
	}()
	configuredSuppressed := e.suppressedInboundTagsSnapshot()
	var instance *core.Instance
	var runtimeDispatcher *mydispatcher.Dispatcher
	err := limiter.WithPersistentInboundSnapshots(func(snapshots []limiter.PersistentInboundSnapshot) error {
		data, err := os.ReadFile(e.configPath)
		if err != nil {
			return err
		}
		missingMappings, err := wireGuardInboundTagsMissingPersistentMappings(data, snapshots)
		if err != nil {
			return err
		}
		suppressed := configuredSuppressed
		if len(missingMappings) > 0 && suppressed == nil {
			suppressed = make(map[string]struct{}, len(missingMappings))
		}
		for tag := range missingMappings {
			suppressed[tag] = struct{}{}
			log.Printf("[EmbeddedXray] Suppressing WireGuard inbound %q: durable limiter mapping is incomplete", tag)
		}

		pbConfig, err := buildCoreConfigJSONWithSuppressedInbounds(data, suppressed)
		if err != nil {
			return err
		}
		instance, err = e.safeNewInstance(pbConfig)
		if err != nil {
			return err
		}
		if feature := instance.GetFeature(mydispatcher.Type()); feature != nil {
			runtimeDispatcher, _ = feature.(*mydispatcher.Dispatcher)
		}
		if len(snapshots) > 0 && (runtimeDispatcher == nil || runtimeDispatcher.Limiter == nil) {
			_ = instance.Close()
			return fmt.Errorf("persistent limiter state is present but the embedded dispatcher is unavailable")
		}
		for _, snapshot := range snapshots {
			runtimeDispatcher.Limiter.SyncInboundLimiterWithSharedLimit(
				snapshot.InboundTag,
				snapshot.NodeLimit,
				snapshot.InboundSharedLimit,
				snapshot.Users,
				snapshot.WireGuardPeers...,
			)
		}
		if err := e.safeInstanceStart(instance); err != nil {
			_ = instance.Close()
			return err
		}
		e.mu.Lock()
		e.instance = instance
		e.statsManager, _ = instance.GetFeature(stats.ManagerType()).(stats.Manager)
		e.dispatcher = runtimeDispatcher
		e.mu.Unlock()
		return nil
	})
	if err != nil {
		return fmt.Errorf("start embedded Xray with durable limiter state: %w", err)
	}

	if e.speedMonitor != nil && runtimeDispatcher != nil {
		e.speedMonitor.SetLimiter(runtimeDispatcher.Limiter)
	}

	log.Printf("[EmbeddedXray] Started successfully")
	return nil
}

func (e *EmbeddedXray) safeNewInstance(pbConfig *core.Config) (inst *core.Instance, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("xray core.New panicked: %v", r)
		}
	}()
	inst, err = core.New(pbConfig)
	return
}

// safeInstanceStart 把 instance.Start 包在 recover 里 — xray-core 启动期 panic 不再带崩 agent 进程。
func (e *EmbeddedXray) safeInstanceStart(inst *core.Instance) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("xray instance.Start panicked: %v", r)
		}
	}()
	return inst.Start()
}

func (e *EmbeddedXray) Stop() (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("xray stop panicked: %v", r)
		}
	}()
	return limiter.WithPersistentStateLock(func() error {
		e.mu.Lock()
		instance := e.instance
		e.instance = nil
		e.dispatcher = nil
		e.statsManager = nil
		e.mu.Unlock()

		if instance != nil {
			return instance.Close()
		}
		return nil
	})
}

func (e *EmbeddedXray) Restart() error {
	log.Printf("[EmbeddedXray] Restarting...")
	if err := e.Stop(); err != nil {
		log.Printf("[EmbeddedXray] Stop error: %v", err)
	}
	// Wait for OS to release listener ports (metrics, gRPC API)
	time.Sleep(500 * time.Millisecond)

	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		lastErr = e.Start()
		if lastErr == nil {
			return nil
		}
		log.Printf("[EmbeddedXray] Start attempt %d failed: %v", attempt, lastErr)
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	return lastErr
}

func (e *EmbeddedXray) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.instance != nil
}

func (e *EmbeddedXray) GetLimiter() *limiter.Limiter {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.dispatcher != nil {
		return e.dispatcher.Limiter
	}
	return nil
}

func (e *EmbeddedXray) UpdateLimiter(tag string, users []limiter.UserInfo) {
	l := e.GetLimiter()
	if l == nil {
		return
	}
	l.UpdateInboundLimiter(tag, users)
}

func (e *EmbeddedXray) GetOnlineUsers(tag string) map[string][]string {
	l := e.GetLimiter()
	if l == nil {
		return nil
	}
	return l.GetOnlineUsers(tag)
}

// AddUser adds a user to an inbound handler.
func (e *EmbeddedXray) AddUser(inboundTag string, user *protocol.User) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	ibm := instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	ctx := context.Background()
	handler, err := ibm.GetHandler(ctx, inboundTag)
	if err != nil {
		return err
	}

	op := &command.AddUserOperation{User: user}
	return op.ApplyInbound(ctx, handler)
}

// RemoveUser removes a user from an inbound handler.
func (e *EmbeddedXray) RemoveUser(inboundTag string, email string) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	ibm := instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	ctx := context.Background()
	handler, err := ibm.GetHandler(ctx, inboundTag)
	if err != nil {
		return err
	}

	op := &command.RemoveUserOperation{Email: email}
	return op.ApplyInbound(ctx, handler)
}

// AddInbound adds a new inbound handler from a core.InboundHandlerConfig.
func (e *EmbeddedXray) AddInbound(config *core.InboundHandlerConfig) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	ibm := instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	rawHandler, err := core.CreateObject(instance, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(feature_inbound.Handler)
	if !ok {
		return errInvalidHandler
	}
	return ibm.AddHandler(context.Background(), handler)
}

// RemoveInbound removes an inbound handler by tag.
func (e *EmbeddedXray) RemoveInbound(tag string) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	ibm := instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	return ibm.RemoveHandler(context.Background(), tag)
}

// ListInbounds returns all inbound handler tags.
func (e *EmbeddedXray) ListInbounds() []string {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return nil
	}

	ibm := instance.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager)
	handlers := ibm.ListHandlers(context.Background())
	tags := make([]string, 0, len(handlers))
	for _, h := range handlers {
		tags = append(tags, h.Tag())
	}
	return tags
}

// AddOutbound adds a new outbound handler.
func (e *EmbeddedXray) AddOutbound(config *core.OutboundHandlerConfig) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	obm := instance.GetFeature(feature_outbound.ManagerType()).(feature_outbound.Manager)
	rawHandler, err := core.CreateObject(instance, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(feature_outbound.Handler)
	if !ok {
		return errInvalidHandler
	}
	return obm.AddHandler(context.Background(), handler)
}

// RemoveOutbound removes an outbound handler by tag.
func (e *EmbeddedXray) RemoveOutbound(tag string) error {
	e.mu.RLock()
	instance := e.instance
	e.mu.RUnlock()
	if instance == nil {
		return errNotRunning
	}

	obm := instance.GetFeature(feature_outbound.ManagerType()).(feature_outbound.Manager)
	return obm.RemoveHandler(context.Background(), tag)
}

// GetTraffic returns a counter value by name pattern (e.g. "user>>>email>>>traffic>>>uplink").
func (e *EmbeddedXray) GetTraffic(name string) int64 {
	e.mu.RLock()
	sm := e.statsManager
	e.mu.RUnlock()
	if sm == nil {
		return 0
	}
	c := sm.GetCounter(name)
	if c == nil {
		return 0
	}
	return c.Value()
}

var (
	errNotRunning     = &EmbeddedError{"xray instance not running"}
	errInvalidHandler = &EmbeddedError{"created object is not a valid handler"}
)

type EmbeddedError struct {
	msg string
}

func (e *EmbeddedError) Error() string { return e.msg }
