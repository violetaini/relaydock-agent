package chitanda

import (
	"context"
	"github.com/violetaini/chitanda/pkg/server"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPlainUDPFullPacketReplayAfterHandlerRecreation(t *testing.T) {
	psk := []byte("test-psk-must-be-at-least-32-bytes-long!!")
	codec, err := server.NewPlainUDPCodec(psk, "replay-node")
	if err != nil {
		t.Fatal(err)
	}
	captured, err := codec.EncodeClientPacket(123, "8.8.8.8:53", []byte("query"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := codec.EncodeClientPacket(124, "8.8.8.8:53", []byte("fresh"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "replay.cache")
	for round := 0; round < 2; round++ {
		var calls atomic.Int32
		d := &mockTestDispatcher{dispatchFn: func(context.Context, xnet.Destination) (*transport.Link, error) {
			calls.Add(1)
			r, w := pipe.New()
			return &transport.Link{Reader: r, Writer: w}, nil
		}}
		h, err := newTestInboundHandler(t, newTestContextWithDispatcher(t, d), &InboundConfig{Psk: string(psk), ServerId: "replay-node", Path: "/audit", Transport: "stream", ReplayFile: state})
		if err != nil {
			t.Fatal(err)
		}
		c := &mockStatConn{remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}}
		c.push(buf.MergeBytes(nil, captured)...)
		if round == 1 {
			c.push(buf.MergeBytes(nil, fresh)...)
		}
		c.Close()
		if err := h.handleUDP(context.Background(), c, d); err != nil && err != net.ErrClosed {
			h.Close()
			t.Fatal(err)
		}
		h.Close()
		if calls.Load() != 1 {
			t.Fatalf("round %d dispatched %d; want only first admission/new association", round, calls.Load())
		}
	}
}

func TestDefaultReplayStateSurvivesUserConfigurationEdits(t *testing.T) {
	t.Setenv("CHITANDA_STATE_DIR", t.TempDir())
	ctx := newTestContextWithDispatcher(t, nil)
	first := &InboundConfig{Psk: "test-psk-must-be-at-least-32-bytes-long!!", ServerId: "node", Transport: "stream", Path: "/audit"}
	h, err := NewInboundHandler(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := h.replays.Accept("test-default-replay", time.Now()); !accepted || err != nil {
		t.Fatal(err)
	}
	h.Close()
	next := &InboundConfig{ServerId: "node", Transport: "stream", Path: "/audit", Users: []*User{
		{Email: "new@example.invalid", Psk: "other-test-psk-must-be-at-least-32-bytes!!"},
		{Email: "existing@example.invalid", Psk: first.Psk},
	}}
	h, err = NewInboundHandler(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if accepted, err := h.replays.Accept("test-default-replay", time.Now()); accepted || err != nil {
		t.Fatalf("configuration reopened nonce: %v %v", accepted, err)
	}
}
