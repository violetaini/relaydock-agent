package chitanda

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/server"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

var reviewKey = []byte("local-review-only-test-key-32-bytes")

type reviewPC struct {
	in, out chan []byte
	done    chan struct{}
	once    sync.Once
}

func newReviewPC() *reviewPC {
	return &reviewPC{in: make(chan []byte, 8), out: make(chan []byte, 8), done: make(chan struct{})}
}
func (p *reviewPC) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case v := <-p.in:
		return copy(b, v), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}, nil
	case <-p.done:
		return 0, nil, net.ErrClosed
	}
}
func (p *reviewPC) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.out <- bytes.Clone(b)
	return len(b), nil
}
func (p *reviewPC) Close() error                     { p.once.Do(func() { close(p.done) }); return nil }
func (p *reviewPC) LocalAddr() net.Addr              { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (p *reviewPC) SetDeadline(time.Time) error      { return nil }
func (p *reviewPC) SetReadDeadline(time.Time) error  { return nil }
func (p *reviewPC) SetWriteDeadline(time.Time) error { return nil }

type reviewWriter struct{ writes chan buf.MultiBuffer }

func (w *reviewWriter) WriteMultiBuffer(b buf.MultiBuffer) error { w.writes <- b; return nil }
func reviewClient(t *testing.T, p *reviewPC) *client.Client {
	t.Helper()
	c, e := client.New(client.Config{Server: "127.0.0.1:9999", PSK: reviewKey, TCPTransport: "stream", ListenPacket: func(context.Context, string, string) (net.PacketConn, error) { return p, nil }})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c
}
func recvReview[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("test operation timed out")
		var z T
		return z
	}
}

func TestReviewOutboundUDPOwnershipAndDestination(t *testing.T) {
	p := newReviewPC()
	defer p.Close()
	c := reviewClient(t, p)
	r, w := pipe.New()
	defer r.Interrupt()
	defer w.Close()
	writer := &reviewWriter{make(chan buf.MultiBuffer, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dest := xnet.UDPDestination(xnet.ParseAddress("192.0.2.1"), 53)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
	h := &OutboundHandler{client: c}
	done := make(chan error, 1)
	go func() { done <- h.Process(ctx, &transport.Link{Reader: r, Writer: writer}, nil) }()
	packet := buf.FromBytes([]byte("query"))
	other := xnet.UDPDestination(xnet.ParseAddress("192.0.2.2"), 5353)
	packet.UDP = &other
	_ = w.WriteMultiBuffer(buf.MultiBuffer{packet})
	encoded := recvReview(t, p.out)
	codec, _ := server.NewPlainUDPCodec(reviewKey)
	sid, target, _, _, _, e := codec.DecodeClientPacket(encoded, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if target != other.NetAddr() {
		t.Errorf("per-packet target ignored: got %s want %s", target, other.NetAddr())
	}
	a, _ := codec.EncodeServerPacket(sid, other.NetAddr(), []byte("AAAA"), time.Now())
	p.in <- a
	first := recvReview(t, writer.writes)
	b, _ := codec.EncodeServerPacket(sid, other.NetAddr(), []byte("BBBB"), time.Now())
	p.in <- b
	second := recvReview(t, writer.writes)
	if string(first[0].Bytes()) != "AAAA" {
		t.Errorf("first datagram overwritten after next receive: %q", first[0].Bytes())
	}
	if first[0].UDP == nil {
		t.Error("response UDP source metadata missing")
	}
	buf.ReleaseMulti(first)
	buf.ReleaseMulti(second)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("Process still blocked after context cancellation")
	}
	p.Close()
}

func TestReviewPipeCloseReadInterrupts(t *testing.T) {
	r, w := pipe.New()
	defer r.Interrupt()
	defer w.Close()
	c := newPipeConn(r, nil)
	done := make(chan error, 1)
	go func() { _, e := c.Read(make([]byte, 1)); done <- e }()
	_ = c.CloseRead()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("CloseRead is a no-op for real Xray pipe.Reader; read remains blocked")
	}
	r.Interrupt()
}

func TestReviewOutboundTCPRemoteEOF(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	srv := server.NewStreamServer(reviewKey, "", nil, func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { b.Write([]byte("bye")); b.Close() }()
		return a, nil
	})
	defer srv.Close()
	go srv.Serve(ln)
	c, e := client.New(client.Config{Server: ln.Addr().String(), PSK: reviewKey, TCPTransport: "stream"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	r, w := pipe.New()
	defer r.Interrupt()
	defer w.Close()
	writer := &reviewWriter{make(chan buf.MultiBuffer, 8)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: xnet.TCPDestination(xnet.ParseAddress("192.0.2.1"), 443)}})
	h := &OutboundHandler{client: c}
	done := make(chan error, 1)
	go func() { done <- h.Process(ctx, &transport.Link{Reader: r, Writer: writer}, nil) }()
	mb := recvReview(t, writer.writes)
	buf.ReleaseMulti(mb)
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Error("remote EOF + canceled context leaves Process blocked on open link.Reader")
	}
	r.Interrupt()
}

type reviewInboundConn struct {
	net.Conn
	data []byte
}

func (c *reviewInboundConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if c.data == nil {
		return nil, io.EOF
	}
	b := buf.FromBytes(c.data)
	c.data = nil
	return buf.MultiBuffer{b}, nil
}

type reviewDispatcher struct {
	writes  *reviewWriter
	readers []*pipe.Reader
}

func (d *reviewDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *reviewDispatcher) Start() error      { return nil }
func (d *reviewDispatcher) Close() error {
	for _, r := range d.readers {
		r.Interrupt()
	}
	return nil
}
func (d *reviewDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	r, _ := pipe.New()
	d.readers = append(d.readers, r)
	return &transport.Link{Reader: r, Writer: d.writes}, nil
}
func (d *reviewDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return nil
}
func TestReviewInboundReplayAcrossAssociations(t *testing.T) {
	p := newReviewPC()
	defer p.Close()
	c := reviewClient(t, p)
	pc, e := c.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	pc.WriteTo([]byte("one authenticated request"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53})
	wire := recvReview(t, p.out)
	codec, _ := server.NewPlainUDPCodec(reviewKey)
	h := &InboundHandler{config: &InboundConfig{Transport: "stream"}, userCodecs: []*server.PlainUDPCodec{codec}, userReplays: make([]udpReplayRegistry, 1)}
	d := &reviewDispatcher{writes: &reviewWriter{make(chan buf.MultiBuffer, 8)}}
	defer d.Close()
	for i := 0; i < 2; i++ {
		a, b := net.Pipe()
		conn := &reviewInboundConn{Conn: a, data: bytes.Clone(wire)}
		_ = h.handleUDP(context.Background(), conn, d)
		a.Close()
		b.Close()
	}
	count := len(d.writes.writes)
	for len(d.writes.writes) > 0 {
		buf.ReleaseMulti(<-d.writes.writes)
	}
	if count != 1 {
		t.Errorf("same encrypted packet accepted across fresh source associations %d times; want 1", count)
	}
}
