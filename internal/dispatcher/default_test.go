package dispatcher

import (
	"context"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"

	"github.com/violetaini/relaydock-agent/internal/limiter"
)

type dispatcherTestReader struct {
	interrupted bool
}

func (*dispatcherTestReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return nil, nil
}

func (r *dispatcherTestReader) Interrupt() {
	r.interrupted = true
}

type dispatcherTestWriter struct {
	closed bool
}

func (*dispatcherTestWriter) WriteMultiBuffer(buf.MultiBuffer) error {
	return nil
}

func (w *dispatcherTestWriter) Close() error {
	w.closed = true
	return nil
}

func TestResolveInboundUserSynthesizesWireGuardUserFromSourceIP(t *testing.T) {
	l := limiter.New()
	const tag = "wg"
	l.AddInboundLimiter(tag, 0, []limiter.UserInfo{{UID: 1, Email: "alice@example.com"}}, limiter.WireGuardPeerUser{
		Address: "10.20.0.2/32",
		Email:   "alice@example.com",
	})

	d := &Dispatcher{Limiter: l}
	inbound := &session.Inbound{
		Tag: tag,
		Source: net.Destination{
			Address: net.ParseAddress("10.20.0.2"),
		},
	}

	user, err := d.resolveInboundUser(inbound)
	if err != nil {
		t.Fatalf("resolveInboundUser: %v", err)
	}
	if user == nil {
		t.Fatal("expected synthetic user")
	}
	if user.Email != "alice@example.com" || user.Level != 0 {
		t.Fatalf("user=%+v", user)
	}
	if inbound.User == nil || inbound.User.Email != user.Email {
		t.Fatalf("inbound user not cached: %+v", inbound.User)
	}
}

func TestResolveInboundUserAllowsMappedWireGuardProbeWithoutUserPolicy(t *testing.T) {
	l := limiter.New()
	const tag = "wg"
	l.AddInboundLimiter(tag, 0, nil, limiter.WireGuardPeerUser{
		Address: "10.20.0.1/32",
		Email:   "probe@relaydock.internal",
	})

	d := &Dispatcher{Limiter: l}
	inbound := &session.Inbound{
		Tag: tag,
		Source: net.Destination{
			Address: net.ParseAddress("10.20.0.1"),
		},
	}

	user, err := d.resolveInboundUser(inbound)
	if err != nil {
		t.Fatalf("resolveInboundUser: %v", err)
	}
	if user == nil || user.Email != "probe@relaydock.internal" {
		t.Fatalf("user=%+v", user)
	}
}

func TestGetLinkRejectsUnknownWireGuardSourceWhenMappingsExist(t *testing.T) {
	l := limiter.New()
	const tag = "wg"
	l.AddInboundLimiter(tag, 0, nil, limiter.WireGuardPeerUser{
		Address: "10.20.0.1/32",
		Email:   "probe@relaydock.internal",
	})
	d := &Dispatcher{Limiter: l}
	inbound := &session.Inbound{
		Tag: tag,
		Source: net.Destination{
			Address: net.ParseAddress("10.20.0.99"),
		},
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	inboundLink, outboundLink, err := d.getLink(ctx)
	if err == nil || !strings.Contains(err.Error(), "unmapped WireGuard source") {
		t.Fatalf("getLink error=%v", err)
	}
	if inboundLink != nil || outboundLink != nil {
		t.Fatalf("rejected source returned links: inbound=%v outbound=%v", inboundLink, outboundLink)
	}
}

func TestGetLinkRejectsWireGuardSourceAfterEmptySnapshot(t *testing.T) {
	l := limiter.New()
	const tag = "wg"
	l.AddInboundLimiter(tag, 0, nil, limiter.WireGuardPeerUser{
		Address: "10.20.0.1/32",
		Email:   "probe@relaydock.internal",
	})
	l.SyncInboundLimiter(tag, 0, nil)

	d := &Dispatcher{Limiter: l}
	inbound := &session.Inbound{
		Tag: tag,
		Source: net.Destination{
			Address: net.ParseAddress("10.20.0.1"),
		},
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	inboundLink, outboundLink, err := d.getLink(ctx)
	if err == nil || !strings.Contains(err.Error(), "unmapped WireGuard source") {
		t.Fatalf("getLink error=%v", err)
	}
	if inboundLink != nil || outboundLink != nil {
		t.Fatalf("rejected source returned links: inbound=%v outbound=%v", inboundLink, outboundLink)
	}
}

func TestGetLinkRejectsDeniedMappedWireGuardUser(t *testing.T) {
	l := limiter.New()
	const tag = "wg"
	l.AddInboundLimiter(tag, 0, []limiter.UserInfo{{UID: 1, Email: "alice@example.com", Denied: true}}, limiter.WireGuardPeerUser{
		Address: "10.20.0.2/32",
		Email:   "alice@example.com",
	})
	d := &Dispatcher{Limiter: l}
	inbound := &session.Inbound{Tag: tag, Source: net.Destination{Address: net.ParseAddress("10.20.0.2")}}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	inboundLink, outboundLink, err := d.getLink(ctx)
	if err == nil || !strings.Contains(err.Error(), "connection limit reached") {
		t.Fatalf("getLink error=%v", err)
	}
	if inboundLink != nil || outboundLink != nil {
		t.Fatalf("denied source returned links: inbound=%v outbound=%v", inboundLink, outboundLink)
	}
}

func TestDispatchLinkRejectsAndClosesUnknownWireGuardSource(t *testing.T) {
	l := limiter.New()
	const tag = "wg"
	l.AddInboundLimiter(tag, 0, nil, limiter.WireGuardPeerUser{
		Address: "10.20.0.1/32",
		Email:   "probe@relaydock.internal",
	})
	d := &Dispatcher{Limiter: l}
	inbound := &session.Inbound{
		Tag: tag,
		Source: net.Destination{
			Address: net.ParseAddress("10.20.0.99"),
		},
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	reader := &dispatcherTestReader{}
	writer := &dispatcherTestWriter{}
	link := &transport.Link{Reader: reader, Writer: writer}

	err := d.DispatchLink(ctx, net.TCPDestination(net.ParseAddress("192.0.2.1"), 443), link)
	if err == nil || !strings.Contains(err.Error(), "unmapped WireGuard source") {
		t.Fatalf("DispatchLink error=%v", err)
	}
	if !reader.interrupted || !writer.closed {
		t.Fatalf("rejected link was not closed: interrupted=%v closed=%v", reader.interrupted, writer.closed)
	}
}

func TestResolveInboundUserDoesNotRejectOrdinaryInboundWithoutWireGuardMappings(t *testing.T) {
	l := limiter.New()
	l.AddInboundLimiter("vless", 0, []limiter.UserInfo{{UID: 1, Email: "alice@example.com"}})
	d := &Dispatcher{Limiter: l}
	inbound := &session.Inbound{
		Tag: "vless",
		Source: net.Destination{
			Address: net.ParseAddress("198.51.100.20"),
		},
	}

	user, err := d.resolveInboundUser(inbound)
	if err != nil {
		t.Fatalf("resolveInboundUser: %v", err)
	}
	if user != nil {
		t.Fatalf("ordinary anonymous inbound unexpectedly synthesized user: %+v", user)
	}
}

func TestResolveInboundUserKeepsExistingUser(t *testing.T) {
	d := &Dispatcher{}
	inbound := &session.Inbound{User: &protocol.MemoryUser{Email: "existing@example.com"}}

	user, err := d.resolveInboundUser(inbound)
	if err != nil {
		t.Fatalf("resolveInboundUser: %v", err)
	}
	if user == nil || user.Email != "existing@example.com" {
		t.Fatalf("user=%+v", user)
	}
}

func TestGetLinkAppliesSharedInboundLimitToAnonymousTraffic(t *testing.T) {
	l := limiter.New()
	const tag = "forward-42-hop-0"
	l.AddInboundLimiterWithSharedLimit(tag, 1<<20, true, nil)
	d := &Dispatcher{Limiter: l}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    tag,
		Source: net.TCPDestination(net.ParseAddress("192.0.2.1"), 12345),
	})

	inbound, outbound, err := d.getLink(ctx)
	if err != nil {
		t.Fatalf("getLink: %v", err)
	}
	if _, ok := inbound.Writer.(*limiter.RateWriter); !ok {
		t.Fatalf("anonymous uplink writer type=%T", inbound.Writer)
	}
	if _, ok := outbound.Writer.(*limiter.RateWriter); !ok {
		t.Fatalf("anonymous downlink writer type=%T", outbound.Writer)
	}
}

func TestDispatchLinkAppliesSharedInboundLimitToAnonymousTraffic(t *testing.T) {
	l := limiter.New()
	const tag = "forward-42-hop-0"
	l.AddInboundLimiterWithSharedLimit(tag, 1<<20, true, nil)
	d := &Dispatcher{Limiter: l}
	link := &transport.Link{Reader: &dispatcherTestReader{}, Writer: &dispatcherTestWriter{}}

	d.limitAnonymousDispatchLink(tag, link)

	if _, ok := link.Reader.(*limiter.RateReader); !ok {
		t.Fatalf("anonymous DispatchLink reader type=%T", link.Reader)
	}
	if _, ok := link.Writer.(*limiter.RateWriter); !ok {
		t.Fatalf("anonymous DispatchLink writer type=%T", link.Writer)
	}
}

func TestAnonymousInboundRequiresExplicitSharedLimitOptIn(t *testing.T) {
	l := limiter.New()
	const tag = "ordinary-dokodemo"
	l.AddInboundLimiter(tag, 1<<20, nil)
	d := &Dispatcher{Limiter: l}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    tag,
		Source: net.TCPDestination(net.ParseAddress("192.0.2.1"), 12345),
	})

	inbound, outbound, err := d.getLink(ctx)
	if err != nil {
		t.Fatalf("getLink: %v", err)
	}
	if _, ok := inbound.Writer.(*limiter.RateWriter); ok {
		t.Fatal("legacy anonymous inbound was limited without explicit opt-in")
	}
	if _, ok := outbound.Writer.(*limiter.RateWriter); ok {
		t.Fatal("legacy anonymous inbound was limited without explicit opt-in")
	}
}
