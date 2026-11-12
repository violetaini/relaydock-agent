package chitanda

import (
	"bytes"
	"context"
	"errors"
	"github.com/violetaini/chitanda/pkg/server"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestReviewCertificateRoundtrip(t *testing.T) {
	in := &InboundConfig{Psk: string(reviewKey), Transport: "h3", CertFile: "server-cert.pem", KeyFile: "server-key.pem"}
	b, e := proto.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	var out InboundConfig
	if e = proto.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	if out.CertFile != in.CertFile || out.KeyFile != in.KeyFile {
		t.Errorf("certificate paths lost after protobuf: cert=%q key=%q; descriptor fields=%d", out.CertFile, out.KeyFile, in.ProtoReflect().Descriptor().Fields().Len())
	}
}

func TestReviewUDPDatagramAtomicity(t *testing.T) {
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
	_ = w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("query"))})
	wire := recvReview(t, p.out)
	codec, _ := server.NewPlainUDPCodec(reviewKey)
	sid, _, _, _, _, e := codec.DecodeClientPacket(wire, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	a, _ := codec.EncodeServerPacket(sid, dest.NetAddr(), bytes.Repeat([]byte("x"), 9000), time.Now())
	p.in <- a
	mb := recvReview(t, writer.writes)
	if len(mb) != 1 {
		sizes := []int32{}
		for _, b := range mb {
			sizes = append(sizes, b.Len())
		}
		t.Errorf("one 9000-byte UDP datagram became %d packets: %v", len(mb), sizes)
	}
	buf.ReleaseMulti(mb)
	cancel()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("UDP Process still blocks after cancellation with no more responses")
	}
	p.Close()
}

type reviewDenyDialer struct{ calls atomic.Int32 }

func (d *reviewDenyDialer) Dial(ctx context.Context, dest xnet.Destination) (stat.Connection, error) {
	if len(session.OutboundsFromContext(ctx)) == 0 {
		panic("dial without Xray outbound context")
	}
	d.calls.Add(1)
	return nil, errors.New("review blocked by Xray dialer")
}
func (d *reviewDenyDialer) DestIpAddress() xnet.IP                                { return nil }
func (d *reviewDenyDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func TestReviewH2PreservesXrayDialer(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Session-OK", "1")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		w.Write([]byte("unexpected direct connection"))
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()
	h, e := NewOutboundHandler(newTestContextWithDispatcher(t, nil), &OutboundConfig{Server: ts.Listener.Addr().String(), ServerName: "localhost", Psk: string(reviewKey), Path: "/review", Transport: "h2", AllowInsecure: true})
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	spy := &reviewDenyDialer{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = withDialer(ctx, spy)
	conn, e := h.client.DialContext(ctx, "tcp", "192.0.2.1:443")
	if conn != nil {
		conn.Close()
	}
	if spy.calls.Load() == 0 {
		t.Errorf("supplied Xray deny dialer never invoked; direct connection error=%v", e)
	}
}

func TestReviewVirtualPacketConnDeadlineWakes(t *testing.T) {
	c := newVirtualPacketConn()
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, _, e := c.ReadFrom(make([]byte, 1500)); done <- e }()
	time.Sleep(20 * time.Millisecond)
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case <-done:
	case <-time.After(120 * time.Millisecond):
		t.Error("virtualPacketConn deadline leaves active ReadFrom blocked")
	}
	c.Close()
}
