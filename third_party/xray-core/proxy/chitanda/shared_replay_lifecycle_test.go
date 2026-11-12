package chitanda

import (
	"testing"
	"time"
)

// Removing one inbound must not consume another inbound's replay ownership.
func TestSharedReplaySurvivesPeerInboundClose(t *testing.T) {
	t.Setenv("CHITANDA_STATE_DIR", t.TempDir())
	ctx := newTestContextWithDispatcher(t, nil)
	config := &InboundConfig{Psk: "test-psk-must-be-at-least-32-bytes-long!!", ServerId: "node", Transport: "stream", Path: "/audit"}
	a, err := NewInboundHandler(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewInboundHandler(ctx, config)
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	defer b.Close()
	if a.replays != b.replays {
		t.Fatal("state was not shared")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if ok, err := b.replays.Accept("peer-still-serving", time.Now()); !ok || err != nil {
		t.Fatalf("closing peer inbound disabled active inbound: accepted=%v err=%v", ok, err)
	}
	now := time.Now()
	if !b.userReplays[0].accept(123, 1, now, uint64(now.Unix())) {
		t.Fatal("closing peer inbound disabled fresh UDP admission")
	}
	if b.userReplays[0].accept(123, 1, now, uint64(now.Unix())) {
		t.Fatal("duplicate UDP packet accepted after peer close")
	}
	// Even a repeated Close must not release the surviving reference.
	a.Close()
	if ok, err := b.replays.Accept("peer-still-serving-again", time.Now()); !ok || err != nil {
		t.Fatalf("repeated close disabled active inbound: accepted=%v err=%v", ok, err)
	}
}
