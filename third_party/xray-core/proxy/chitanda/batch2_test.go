package chitanda

import (
	"sync"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/server"
	"github.com/xtls/xray-core/transport/pipe"
)

// TestUDPReplayAcrossAssociations verifies P1 issue 4:
// When the same packet/sequence is sent via different connections/associations,
// tracking by authenticated sessionID prevents replay attacks.
func TestUDPReplayAcrossAssociations(t *testing.T) {
	var udpReplays sync.Map

	acceptPacket := func(sessionID uint64, seq uint64) bool {
		var replay *server.UDPReplayWindow
		if val, ok := udpReplays.Load(sessionID); ok {
			replay = val.(*server.UDPReplayWindow)
		} else {
			actual, _ := udpReplays.LoadOrStore(sessionID, server.NewUDPReplayWindow())
			replay = actual.(*server.UDPReplayWindow)
		}
		return replay.Accept(seq)
	}

	sessionA := uint64(0x1122334455667788)

	// Packet 1 from association 1 (port 10001)
	if !acceptPacket(sessionA, 1) {
		t.Fatalf("first packet seq=1 should be accepted")
	}

	// Packet 2 from association 1 (port 10001)
	if !acceptPacket(sessionA, 2) {
		t.Fatalf("second packet seq=2 should be accepted")
	}

	// Attacker captures packet 1 (seq=1) and replays it from association 2 (port 20002)
	if acceptPacket(sessionA, 1) {
		t.Fatalf("replayed packet seq=1 from association 2 MUST be rejected!")
	}

	// Attacker captures packet 2 (seq=2) and replays it from association 3 (port 30003)
	if acceptPacket(sessionA, 2) {
		t.Fatalf("replayed packet seq=2 from association 3 MUST be rejected!")
	}

	// Fresh packet 3 from association 2 should be accepted
	if !acceptPacket(sessionA, 3) {
		t.Fatalf("new packet seq=3 from association 2 should be accepted")
	}
}

// TestPipeConnCloseReadAndDeadline verifies P1 issue 3:
// pipeConn.CloseRead() and SetReadDeadline() genuinely interrupt blocked reads on Xray pipe.
func TestPipeConnCloseReadAndDeadline(t *testing.T) {
	pipeReader, pipeWriter := pipe.New(pipe.WithSizeLimit(1024))
	pConn := newPipeConn(pipeReader, pipeWriter)
	defer pConn.Close()

	// Test 1: SetReadDeadline interrupts blocked read
	pConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 10)
	start := time.Now()
	_, err := pConn.Read(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("expected Read to fail due to deadline interrupt, got nil")
	}
	if elapsed < 30*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Fatalf("expected Read to unblock around 50ms, took %v", elapsed)
	}

	// Test 2: CloseRead() interrupts blocked read immediately
	pipeReader2, pipeWriter2 := pipe.New(pipe.WithSizeLimit(1024))
	pConn2 := newPipeConn(pipeReader2, pipeWriter2)
	defer pConn2.Close()

	done := make(chan error, 1)
	go func() {
		_, err := pConn2.Read(buf)
		done <- err
	}()

	time.Sleep(20 * time.Millisecond)
	_ = pConn2.CloseRead()

	select {
	case readErr := <-done:
		if readErr == nil {
			t.Fatalf("expected read error after CloseRead, got nil")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("CloseRead failed to unblock blocked reader within 200ms!")
	}
}
