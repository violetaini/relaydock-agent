package chitanda

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/server"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func newTestContextWithDispatcher(t *testing.T, disp routing.Dispatcher) context.Context {
	v, err := core.New(&core.Config{})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	if disp == nil {
		disp = &mockTestDispatcher{}
	}
	if err := v.AddFeature(disp); err != nil {
		t.Fatalf("AddFeature: %v", err)
	}
	return context.WithValue(context.Background(), core.XrayKey(1), v)
}

func TestH3InboundInitialization(t *testing.T) {
	ctx := newTestContextWithDispatcher(t, nil)
	psk := "test-psk-must-be-at-least-32-bytes-long!!"

	// 1. H3 transport -> H3 enabled
	h3Handler, err := newTestInboundHandler(t, ctx, &InboundConfig{
		Psk:       psk,
		Path:      "/api/sync",
		Transport: "h3",
		StrictSni: "localhost",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler h3: %v", err)
	}
	if h3Handler.h3Server == nil || h3Handler.vconn == nil {
		t.Fatal("expected h3Server and vconn to be initialized for transport=h3")
	}
	_ = h3Handler.Close()

	// 2. Stream transport -> H3 disabled
	streamHandler, err := newTestInboundHandler(t, ctx, &InboundConfig{
		Psk:       psk,
		Path:      "/api/sync",
		Transport: "stream",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler stream: %v", err)
	}
	if streamHandler.h3Server != nil || streamHandler.vconn != nil {
		t.Fatal("expected h3Server and vconn to be nil for transport=stream")
	}
	_ = streamHandler.Close()

	// 3. Auto transport -> H3 enabled
	autoHandler, err := newTestInboundHandler(t, ctx, &InboundConfig{
		Psk:       psk,
		Path:      "/api/sync",
		Transport: "auto",
		StrictSni: "localhost",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler auto: %v", err)
	}
	if autoHandler.h3Server == nil || autoHandler.vconn == nil {
		t.Fatal("expected h3Server and vconn to be initialized for transport=auto")
	}
	_ = autoHandler.Close()

	// 4. H2 transport -> H3 enabled (for H3 UDP)
	h2Handler, err := newTestInboundHandler(t, ctx, &InboundConfig{
		Psk:       psk,
		Path:      "/api/sync",
		Transport: "h2",
		StrictSni: "localhost",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler h2: %v", err)
	}
	if h2Handler.h3Server == nil || h2Handler.vconn == nil {
		t.Fatal("expected h3Server and vconn to be initialized for transport=h2")
	}
	_ = h2Handler.Close()
}

func TestQUICPacketDetection(t *testing.T) {
	// Too short (< 20 bytes)
	if isQUICPacket([]byte{0xc0, 0x01, 0x02}) {
		t.Error("expected false for short packet")
	}

	// Long Header Initial packet with Fixed Bit set (0xc0 = 1100 0000)
	initialPkt := make([]byte, 1200)
	initialPkt[0] = 0xc0 // Long header + Fixed bit (0x40)
	initialPkt[1] = 0x00
	initialPkt[2] = 0x00
	initialPkt[3] = 0x00
	initialPkt[4] = 0x01 // QUIC version 1
	if !isQUICPacket(initialPkt) {
		t.Error("expected true for QUIC Initial packet")
	}

	// Short Header 1-RTT packet with Fixed Bit set (0x40 = 0100 0000)
	oneRttPkt := make([]byte, 32)
	oneRttPkt[0] = 0x40 // Short header + Fixed bit (0x40)
	if !isQUICPacket(oneRttPkt) {
		t.Error("expected true for QUIC 1-RTT packet")
	}

	// Invalid packet with Fixed Bit clear (0x00 = 0000 0000)
	invalidPkt := make([]byte, 32)
	invalidPkt[0] = 0x00
	if isQUICPacket(invalidPkt) {
		t.Error("expected false when fixed bit is 0")
	}
}

func TestVirtualPacketConn(t *testing.T) {
	vconn := newVirtualPacketConn()
	defer vconn.Close()

	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 54321}
	mockConn := &mockStatConn{
		remoteAddr: clientAddr,
		localAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
	}

	vconn.registerConn(clientAddr.String(), mockConn)

	// Feed a packet
	testPayload := []byte("hello quic")
	vconn.feed(testPayload, clientAddr)

	buf := make([]byte, 1024)
	n, addr, err := vconn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if n != len(testPayload) || string(buf[:n]) != string(testPayload) {
		t.Fatalf("unexpected data: got %q, want %q", string(buf[:n]), string(testPayload))
	}
	if addr.String() != clientAddr.String() {
		t.Fatalf("unexpected addr: got %v, want %v", addr, clientAddr)
	}

	// WriteTo back to client
	reply := []byte("quic response")
	wn, err := vconn.WriteTo(reply, clientAddr)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if wn != len(reply) {
		t.Fatalf("WriteTo short write: %d vs %d", wn, len(reply))
	}
	if len(mockConn.written) != 1 || string(mockConn.written[0]) != string(reply) {
		t.Fatalf("unexpected mockConn written data: %v", mockConn.written)
	}

	// Unregister
	vconn.unregisterConn(clientAddr.String(), mockConn)
	_, err = vconn.WriteTo(reply, clientAddr)
	if err == nil {
		t.Fatal("expected error after unregistering conn")
	}
}

func TestH3AndPlainUDPDemuxing(t *testing.T) {
	psk := []byte("test-psk-must-be-at-least-32-bytes-long!!")
	var plainDispatched atomic.Bool
	mockDispatcher := &mockTestDispatcher{
		dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
			if dest.Network == xnet.Network_UDP && dest.Address.String() == "8.8.8.8" {
				plainDispatched.Store(true)
			}
			pReader, pWriter := pipe.New()
			return &transport.Link{Reader: pReader, Writer: pWriter}, nil
		},
	}

	ctx := newTestContextWithDispatcher(t, mockDispatcher)
	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 12345}

	codec, err := server.NewPlainUDPCodec(psk)
	if err != nil {
		t.Fatalf("NewPlainUDPCodec: %v", err)
	}

	// A Plain-UDP nonce is random. Select an authentic packet whose QUIC fixed
	// bit is clear, so only the trailing QUIC packet can trigger onFeed below.
	var plainPkt []byte
	for attempt := 0; attempt < 64; attempt++ {
		plainPkt, err = codec.EncodeClientPacket(1001, "8.8.8.8:53", []byte("dns query"), time.Now())
		if err != nil {
			t.Fatalf("EncodeClientPacket: %v", err)
		}
		if !isQUICPacket(plainPkt) {
			break
		}
	}
	if isQUICPacket(plainPkt) {
		t.Fatal("could not generate a valid Plain-UDP packet distinguishable from QUIC")
	}
	if _, _, _, _, _, err := codec.DecodeClientPacket(plainPkt, time.Now()); err != nil {
		t.Fatalf("selected Plain-UDP packet must remain authentic: %v", err)
	}

	quicPkt := make([]byte, 1200)
	quicPkt[0] = 0xc0 // Long Header + Fixed Bit
	quicPkt[1] = 0x00
	quicPkt[2] = 0x00
	quicPkt[3] = 0x00
	quicPkt[4] = 0x01
	copy(quicPkt[20:], []byte("quic initial payload"))

	// 1. Auto/H3 Inbound handles QUIC packets directly via vconn and refuses Plain-UDP trial decryption.
	// We instantiate a genuine "auto" inbound handler to verify its authentic runtime state.
	hAuto, err := newTestInboundHandler(t, ctx, &InboundConfig{
		Psk:       string(psk),
		Path:      "/api/sync",
		Transport: "auto",
		StrictSni: "localhost",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler auto: %v", err)
	}
	defer hAuto.Close()

	if hAuto.userCodecs != nil || hAuto.userReplays != nil {
		t.Fatal("auto inbound must not initialize plain-udp codecs/replays")
	}
	if hAuto.h3Server == nil || hAuto.vconn == nil {
		t.Fatal("auto inbound must initialize h3Server and vconn")
	}

	quicFed := make(chan struct{}, 1)
	hAuto.vconn.onFeed = func() {
		select {
		case quicFed <- struct{}{}:
		default:
		}
	}

	quicConn := &mockStatConn{
		remoteAddr: clientAddr,
		localAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443},
	}
	go func() {
		_ = hAuto.handleUDP(context.Background(), quicConn, mockDispatcher)
	}()

	// Push authentic Plain-UDP packet first, followed immediately by valid QUIC packet.
	// Because handleUDP processes packets strictly in FIFO order from quicConn,
	// when the trailing QUIC packet arrives and triggers onFeed, the leading Plain-UDP
	// packet is guaranteed to have already been evaluated and dropped.
	quicConn.push(buf.MergeBytes(nil, plainPkt)...)
	quicConn.push(buf.MergeBytes(nil, quicPkt)...)

	select {
	case <-quicFed:
		// Trailing QUIC packet was processed and fed to vconn!
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for QUIC packet to be fed to vconn")
	}

	// Strictly assert with causal ordering (zero arbitrary sleep):
	// Even though an authentic, valid Plain-UDP packet was received right before the QUIC packet,
	// it was NEVER trial-decrypted or dispatched to mockDispatcher.
	if plainDispatched.Load() {
		t.Fatal("auto inbound unexpectedly trial-decrypted and dispatched authentic Plain-UDP packet")
	}
	_ = quicConn.Close()

	// 2. Stream Inbound handles Plain-UDP packets via dispatcher and refuses QUIC packets.
	var streamDispatchCount atomic.Int32
	mockDispatcherStream := &mockTestDispatcher{
		dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
			if dest.Network == xnet.Network_UDP && dest.Address.String() == "8.8.8.8" {
				streamDispatchCount.Add(1)
			}
			pReader, pWriter := pipe.New()
			return &transport.Link{Reader: pReader, Writer: pWriter}, nil
		},
	}
	ctxStream := newTestContextWithDispatcher(t, mockDispatcherStream)
	hStream, err := newTestInboundHandler(t, ctxStream, &InboundConfig{
		Psk:       string(psk),
		Path:      "/api/sync",
		Transport: "stream",
	})
	if err != nil {
		t.Fatalf("NewInboundHandler stream: %v", err)
	}
	defer hStream.Close()

	if hStream.h3Server != nil || hStream.vconn != nil {
		t.Fatal("stream inbound must not initialize h3Server or vconn")
	}
	if hStream.userCodecs == nil || len(hStream.userCodecs) != 1 {
		t.Fatal("stream inbound must initialize plain-udp codecs")
	}

	plainConn := &mockStatConn{
		remoteAddr: clientAddr,
		localAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443},
	}
	go func() {
		_ = hStream.handleUDP(context.Background(), plainConn, mockDispatcherStream)
	}()

	// Push invalid/QUIC packet first, followed immediately by authentic Plain-UDP packet.
	// In FIFO order, when plainPkt triggers dispatch, quicPkt has already been processed.
	plainConn.push(buf.MergeBytes(nil, quicPkt)...)
	plainConn.push(buf.MergeBytes(nil, plainPkt)...)

	deadline := time.Now().Add(2 * time.Second)
	for streamDispatchCount.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if streamDispatchCount.Load() == 0 {
		t.Fatal("Plain-UDP packet was not dispatched to upstream")
	}
	// The dispatch count must be EXACTLY 1 (for plainPkt only, proving quicPkt was dropped without dispatch)
	if streamDispatchCount.Load() != 1 {
		t.Fatalf("expected exactly 1 dispatch for plain packet, got %d (quic packet dispatched unexpectedly)", streamDispatchCount.Load())
	}

	_ = plainConn.Close()
}

type mockTestDispatcher struct {
	dispatchFn func(ctx context.Context, dest xnet.Destination) (*transport.Link, error)
}

func (m *mockTestDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

func (m *mockTestDispatcher) Start() error { return nil }
func (m *mockTestDispatcher) Close() error { return nil }

func (m *mockTestDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	if m.dispatchFn != nil {
		return m.dispatchFn(ctx, dest)
	}
	pReader, pWriter := pipe.New()
	return &transport.Link{Reader: pReader, Writer: pWriter}, nil
}

func (m *mockTestDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	return nil
}

type mockStatConn struct {
	remoteAddr net.Addr
	localAddr  net.Addr
	readBuf    buf.MultiBuffer
	written    [][]byte
	closed     bool
	mu         sync.Mutex
	cond       *sync.Cond
}

func (m *mockStatConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for len(m.readBuf) == 0 && !m.closed {
		if m.cond == nil {
			m.cond = sync.NewCond(&m.mu)
		}
		m.cond.Wait()
	}
	if m.closed && len(m.readBuf) == 0 {
		return nil, net.ErrClosed
	}
	mb := m.readBuf
	m.readBuf = nil
	return mb, nil
}

func (m *mockStatConn) push(buffers ...*buf.Buffer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readBuf = append(m.readBuf, buffers...)
	if m.cond != nil {
		m.cond.Broadcast()
	}
}

func (m *mockStatConn) Read(b []byte) (int, error) {
	return 0, nil
}

func (m *mockStatConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]byte, len(b))
	copy(copied, b)
	m.written = append(m.written, copied)
	return len(b), nil
}

func (m *mockStatConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	if m.cond != nil {
		m.cond.Broadcast()
	}
	return nil
}

func (m *mockStatConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockStatConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockStatConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockStatConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockStatConn) SetWriteDeadline(t time.Time) error { return nil }

func TestH3DialTargetRouting(t *testing.T) {
	srv := server.NewServer("/test", []byte("01234567890123456789012345678901"), nil, nil, 10)
	srv.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	})

	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
	h3Srv := server.NewHTTP3Server(srv, tlsConfig, 0)
	if h3Srv == nil {
		t.Fatal("expected NewHTTP3Server to return non-nil server")
	}
}
