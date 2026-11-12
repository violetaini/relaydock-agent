package chitanda

import (
	"context"
	"github.com/violetaini/chitanda/pkg/client"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"io"
	"net"
	"testing"
	"time"
)

func TestInboundH2FlowControlWindow(t *testing.T) {
	s := newInboundH2Server()
	const wantConnWindow = 64 * 1024 * 1024
	const wantStreamWindow = 32 * 1024 * 1024
	if s.MaxUploadBufferPerConnection != wantConnWindow || s.MaxUploadBufferPerStream != wantStreamWindow {
		t.Fatalf("Xray H2 upload windows are %d/%d, want %d/%d; the default window throttles a single stream over WAN RTT",
			s.MaxUploadBufferPerConnection, s.MaxUploadBufferPerStream, wantConnWindow, wantStreamWindow)
	}
	if s.MaxReadFrameSize != 1<<20 || s.IdleTimeout != 3*time.Minute {
		t.Fatalf("Xray H2 frame/idle settings drifted from the standalone server: %d/%s", s.MaxReadFrameSize, s.IdleTimeout)
	}
}

type reviewUDPBridge struct {
	*net.UDPConn
	remote net.Addr
}

func (c *reviewUDPBridge) RemoteAddr() net.Addr        { return c.remote }
func (c *reviewUDPBridge) Write(b []byte) (int, error) { return c.UDPConn.WriteTo(b, c.remote) }
func (c *reviewUDPBridge) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.NewWithSize(65535)
	n, _, e := c.UDPConn.ReadFrom(b.Extend(65535))
	if e != nil {
		b.Release()
		return nil, e
	}
	b.Resize(0, int32(n))
	return buf.MultiBuffer{b}, nil
}

func TestReviewH3RealAdapterContextAndShutdown(t *testing.T) {
	srvPC, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer srvPC.Close()
	cliPC, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer cliPC.Close()
	tags := make(chan string, 4)
	disp := &mockTestDispatcher{dispatchFn: func(ctx context.Context, d xnet.Destination) (*transport.Link, error) {
		tag := "<nil>"
		if in := session.InboundFromContext(ctx); in != nil {
			tag = in.Tag
		}
		tags <- tag
		r, w := pipe.New()
		return &transport.Link{Reader: r, Writer: w}, nil
	}}
	h, e := newTestInboundHandler(t, newTestContextWithDispatcher(t, disp), &InboundConfig{Psk: string(reviewKey), Path: "/review", Transport: "h3", StrictSni: "localhost"})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { h.vconn.Close(); h.Close() }()
	bridge := &reviewUDPBridge{UDPConn: srvPC, remote: cliPC.LocalAddr()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "expected-production-inbound", Source: xnet.UDPDestination(xnet.ParseAddress("192.0.2.10"), 1234)})
	go h.Process(ctx, xnet.Network_UDP, bridge, disp)
	c, e := client.New(client.Config{Server: srvPC.LocalAddr().String(), ServerName: "localhost", PSK: reviewKey, Path: "/review", TCPTransport: "h3", InsecureSkipVerify: true, ListenPacket: func(context.Context, string, string) (net.PacketConn, error) { return cliPC, nil }})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dcancel()
	conn, e := c.DialContext(dctx, "tcp", "192.0.2.1:443")
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, e = conn.Write([]byte("ping")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 4)
	if _, e = io.ReadFull(conn, b); e != nil {
		t.Fatal(e)
	}
	t.Logf("real H3/Xray bridge TCP echo=%q", b)
	if tag := recvReview(t, tags); tag != "expected-production-inbound" {
		t.Errorf("H3 dropped inbound metadata: got tag=%q", tag)
	}
	conn.Close()
	c.Close()
	srvPC.Close()
	done := make(chan struct{})
	go func() { h.Close(); close(done) }()
	select {
	case <-done:
		t.Log("H3 handler shutdown completed")
	case <-time.After(250 * time.Millisecond):
		t.Error("H3 handler Close blocked; virtual read must be explicitly unblocked")
		h.vconn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("shutdown remained blocked")
		}
	}
}

func TestReviewH1RealAdapterContext(t *testing.T) {
	tags := make(chan string, 1)
	disp := &mockTestDispatcher{dispatchFn: func(ctx context.Context, d xnet.Destination) (*transport.Link, error) {
		tag := "<nil>"
		if in := session.InboundFromContext(ctx); in != nil {
			tag = in.Tag
		}
		tags <- tag
		r, w := pipe.New()
		return &transport.Link{Reader: r, Writer: w}, nil
	}}
	h, e := newTestInboundHandler(t, newTestContextWithDispatcher(t, disp), &InboundConfig{Psk: string(reviewKey), Path: "/review", Transport: "h1"})
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "expected-production-inbound"})
	go func() {
		p, e := ln.Accept()
		if e == nil {
			h.Process(ctx, xnet.Network_TCP, p, disp)
		}
	}()
	c, e := client.New(client.Config{Server: ln.Addr().String(), PSK: reviewKey, Path: "/review", TCPTransport: "h1"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	dctx, dcancel := context.WithTimeout(context.Background(), time.Second)
	defer dcancel()
	conn, e := c.DialContext(dctx, "tcp", "192.0.2.1:80")
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if tag := recvReview(t, tags); tag != "expected-production-inbound" {
		t.Errorf("H1 dropped inbound metadata: got tag=%q", tag)
	}
}
