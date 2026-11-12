package chitanda

import (
	"testing"
	"time"
)

func TestUDPReplayRegistryCapacityAndSafeExpiry(t *testing.T) {
	var r udpReplayRegistry
	now := time.Now()
	for id := uint64(0); id < maxUDPReplaySessions; id++ {
		if !r.accept(id, 1, now) {
			t.Fatalf("session %d rejected before capacity", id)
		}
	}
	if r.accept(maxUDPReplaySessions, 1, now) {
		t.Fatal("registry exceeded capacity")
	}
	if r.accept(0, 1, now.Add(time.Second)) {
		t.Fatal("capacity reopened a replay")
	}
	r.expire(now.Add(60 * time.Second))
	if len(r.entries) != maxUDPReplaySessions {
		t.Fatal("window expired before captured packets became stale")
	}
	if !r.accept(0, 2, now.Add(64*time.Second)) {
		t.Fatal("active session blocked at capacity")
	}
	r.expire(now.Add(66 * time.Second))
	if len(r.entries) != 1 {
		t.Fatalf("expected one active window, got %d", len(r.entries))
	}
	if r.accept(0, 2, now.Add(66*time.Second)) {
		t.Fatal("active window reopened")
	}
	if !r.accept(maxUDPReplaySessions, 1, now.Add(66*time.Second)) {
		t.Fatal("expired capacity not reusable")
	}
}
