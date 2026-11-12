package chitanda

import (
	"context"
	"errors"
	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/server"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRegressionMultiplexedContextIsolation(t *testing.T) {
	var contexts []context.Context
	d := &mockTestDispatcher{dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
		contexts = append(contexts, ctx)
		return nil, errors.New("audit: do not connect")
	}}
	h, e := newTestInboundHandler(t, newTestContextWithDispatcher(t, d), &InboundConfig{Psk: string(reviewKey), Path: "/audit", Transport: "h2"})
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	ctx = session.ContextWithContent(ctx, &session.Content{})
	for i, target := range []string{"first.invalid:443", "second.invalid:443"} {
		req := httptest.NewRequest("POST", "https://localhost/audit", strings.NewReader("")).WithContext(ctx)
		req.ProtoMajor = 2
		ts, nonce := strconv.FormatInt(time.Now().Unix(), 10), "audit-nonce-"+strconv.Itoa(i)
		req.Header.Set("X-Session-Target", target)
		req.Header.Set("X-Session-Time", ts)
		req.Header.Set("X-Session-Nonce", nonce)
		req.Header.Set("X-Session-Mode", "tcp-v2")
		req.Header.Set("X-Session-Auth", auth.Signature(reviewKey, "tcp-v2", "POST", "/audit", target, ts, nonce))
		h.server.ServeHTTP(httptest.NewRecorder(), req)
	}
	if len(contexts) != 2 {
		t.Fatalf("dispatch count=%d", len(contexts))
	}
	if session.OutboundsFromContext(contexts[0])[0] == session.OutboundsFromContext(contexts[1])[0] {
		t.Error("independent H2 streams share mutable Xray session.Outbound")
	}
	if session.ContentFromContext(contexts[0]) == session.ContentFromContext(contexts[1]) {
		t.Error("independent H2 streams share mutable sniffing Content")
	}
}

func TestRegressionNativeUDPPerTargetRouting(t *testing.T) {
	srv, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer srv.Close()
	cli, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer cli.Close()
	dispatched := make(chan string, 4)
	d := &mockTestDispatcher{dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
		dispatched <- dest.NetAddr()
		r, w := pipe.New()
		return &transport.Link{Reader: r, Writer: w}, nil
	}}
	h, e := newTestInboundHandler(t, newTestContextWithDispatcher(t, d), &InboundConfig{Psk: string(reviewKey), Path: "/audit", Transport: "stream"})
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- h.Process(ctx, xnet.Network_UDP, &reviewUDPBridge{UDPConn: srv, remote: cli.LocalAddr()}, d)
	}()
	codec, _ := server.NewPlainUDPCodec(reviewKey)
	for _, target := range []string{"first.invalid:53", "second.invalid:53"} {
		pkt, e := codec.EncodeClientPacket(123, target, []byte("query"), time.Now())
		if e != nil {
			t.Fatal(e)
		}
		if _, e = cli.WriteTo(pkt, srv.LocalAddr()); e != nil {
			t.Fatal(e)
		}
		cli.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, e = cli.ReadFrom(make([]byte, 2048)); e != nil {
			t.Fatal(e)
		}
	}
	if len(dispatched) != 2 {
		t.Errorf("two distinct UDP targets only triggered %d routing decision(s)", len(dispatched))
	}
	cancel()
	srv.Close()
	<-done
}

func TestRegressionHTTPPartialHeaderBudget(t *testing.T) {
	h, e := newTestInboundHandler(t, newTestContextWithDispatcher(t, nil), &InboundConfig{Psk: string(reviewKey), Path: "/audit", Transport: "h1"})
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.Process(ctx, xnet.Network_TCP, a, nil) }()
	if _, e = b.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nX-Incomplete: ")); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
		return
	case <-time.After(2300 * time.Millisecond):
		t.Error("unauthenticated incomplete headers survive cleared 2s handshake deadline; HTTP server has no ReadHeaderTimeout")
	}
	cancel()
	b.Close()
	<-done
}
