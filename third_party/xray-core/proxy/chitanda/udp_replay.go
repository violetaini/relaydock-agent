package chitanda

import (
	"context"
	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/server"
	"sync"
	"time"
)

const maxUDPReplaySessions = 10000

// A packet can arrive 30s ahead of its timestamp and remain valid for another
// 30s. Never expire a window before every previously accepted packet is stale.
const udpReplayRetention = 65 * time.Second

type udpReplayEntry struct {
	window *server.UDPReplayWindow
	last   time.Time
}
type udpReplayRegistry struct {
	mu        sync.Mutex
	entries   map[uint64]*udpReplayEntry
	closed    bool
	cache     *auth.ReplayCache
	namespace string
}

func (r *udpReplayRegistry) accept(id, seq uint64, now time.Time, timestamps ...uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	if r.entries == nil {
		r.entries = make(map[uint64]*udpReplayEntry)
	}
	e := r.entries[id]
	if e == nil {
		// Fail closed at capacity: evicting a live window would reopen replays.
		if len(r.entries) >= maxUDPReplaySessions {
			return false
		}
		e = &udpReplayEntry{window: server.NewPersistentUDPReplayWindow(r.cache, r.namespace, id)}
		r.entries[id] = e
	}
	accepted := false
	if len(timestamps) > 0 {
		accepted = e.window.AcceptAuthenticated(seq, timestamps[0], now)
	} else {
		accepted = e.window.Accept(seq)
	}
	if !accepted {
		return false
	}
	e.last = now
	return true
}

func (r *udpReplayRegistry) expire(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, e := range r.entries {
		if now.Sub(e.last) > udpReplayRetention {
			delete(r.entries, id)
		}
	}
}

func (r *udpReplayRegistry) run(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	defer func() { r.mu.Lock(); r.closed = true; r.entries = nil; r.mu.Unlock() }()
	for {
		select {
		case now := <-t.C:
			r.expire(now)
		case <-ctx.Done():
			return
		}
	}
}
