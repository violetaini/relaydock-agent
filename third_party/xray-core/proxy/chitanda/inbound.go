package chitanda

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/connio"
	"github.com/violetaini/chitanda/pkg/server"

	"golang.org/x/net/http2"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// InboundHandler implements proxy.Inbound for Chitanda protocol in Xray
type InboundHandler struct {
	config       *InboundConfig
	users        []server.UserKey
	server       *server.Server
	streamServer *server.StreamServer
	h3Server     *http3.Server
	vconn        *virtualPacketConn
	userCodecs   []*server.PlainUDPCodec
	replays      *auth.ReplayCache
	userReplays  []udpReplayRegistry
	dispatcher   routing.Dispatcher
	dialICMP     func(ctx context.Context, address string) (net.PacketConn, error)
	tcpTLSConfig *tls.Config
	ctx          context.Context
	cancel       context.CancelFunc
	httpSlots    chan struct{}
	closeOnce    sync.Once
}

func NewInboundHandler(ctx context.Context, config *InboundConfig) (*InboundHandler, error) {
	if config == nil {
		return nil, fmt.Errorf("chitanda: inbound config is required")
	}
	if len(config.Users) > 0 && config.Psk != "" {
		return nil, fmt.Errorf("chitanda: psk and users cannot be configured together")
	}
	if len(config.Users) == 0 && len(config.Psk) < 32 {
		return nil, fmt.Errorf("chitanda: psk must contain at least 32 bytes")
	}
	switch config.Transport {
	case "", "stream", "h1", "plain-h1", "h2", "h3", "auto":
	default:
		return nil, fmt.Errorf("chitanda: unsupported transport %q", config.Transport)
	}
	var serverUsers []server.UserKey
	if len(config.Users) > 0 {
		serverUsers = make([]server.UserKey, 0, len(config.Users))
		for i, user := range config.Users {
			if user == nil {
				return nil, fmt.Errorf("chitanda: user %d is nil", i)
			}
			email := strings.TrimSpace(user.Email)
			if email == "" {
				return nil, fmt.Errorf("chitanda: user %d has no email", i)
			}
			serverUsers = append(serverUsers, server.UserKey{Email: email, PSK: []byte(user.Psk), Level: user.Level})
		}
	} else {
		serverUsers = []server.UserKey{{PSK: []byte(config.Psk)}}
	}
	if err := server.ValidateUserKeys(serverUsers); err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	dispatcher := v.GetFeature(routing.DispatcherType()).(routing.Dispatcher)

	var replays *auth.ReplayCache
	var err error
	replayPath := config.ReplayFile
	if replayPath == "" {
		// Configuration edits (including adding/reordering users) must not
		// reset recent replay admissions. Share a stable account-level store.
		replayPath, err = auth.DefaultReplayPath("xray-auth-v3")
		if err != nil {
			return nil, fmt.Errorf("default replay state: %w", err)
		}
	}
	replays, err = auth.OpenSharedReplayCache(replayPath, time.Now())
	if err != nil {
		return nil, fmt.Errorf("open replay cache: %w", err)
	}

	var fbHandler http.Handler
	if config.Fallback != "" {
		fb, err := server.NewFallback(config.Fallback, config.StrictSni)
		if err != nil {
			_ = replays.Close()
			return nil, fmt.Errorf("init fallback handler: %w", err)
		}
		fbHandler = fb
	}

	dialTargetFn := func(ctx context.Context, network, address string) (net.Conn, error) {
		if network == "" {
			network = "tcp"
		}
		dest, err := xnet.ParseDestination(network + ":" + address)
		if err != nil {
			return nil, err
		}

		reqCtx := requestContext(ctx)
		inbound := session.InboundFromContext(reqCtx)
		if u, ok := server.UserFromContext(ctx); ok && u != nil && u.Email != "" {
			inbound.User = &protocol.MemoryUser{
				Email: u.Email,
				Level: u.Level,
			}
		}

		link, err := dispatcher.Dispatch(reqCtx, dest)
		if err != nil {
			return nil, err
		}

		if network == "udp" {
			return newPacketLinkConn(link.Reader, link.Writer, packetAddress(address)), nil
		}
		return newPipeConn(link.Reader, link.Writer), nil
	}

	var srv *server.Server
	var streamSrv *server.StreamServer
	if len(config.Users) > 0 {
		srv, err = server.NewServerWithUsers(config.Path, serverUsers, replays, fbHandler, 1024)
		if err != nil {
			_ = replays.Close()
			return nil, err
		}
		streamSrv, err = server.NewStreamServerWithUsers(serverUsers, config.ServerId, replays, func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialTargetFn(ctx, network, address)
		})
		if err != nil {
			_ = replays.Close()
			return nil, err
		}
	} else {
		srv = server.NewServer(config.Path, serverUsers[0].PSK, replays, fbHandler, 1024)
		streamSrv = server.NewStreamServer(serverUsers[0].PSK, config.ServerId, replays, func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialTargetFn(ctx, network, address)
		})
	}
	srv.SetDialTargetForTest(func(ctx context.Context, address string) (net.Conn, error) {
		return dialTargetFn(ctx, "tcp", address)
	})
	srv.SetDialUDP(func(ctx context.Context, address string) (net.Conn, error) {
		return dialTargetFn(ctx, "udp", address)
	})
	dialICMPFn := func(ctx context.Context, address string) (net.PacketConn, error) {
		ip := net.ParseIP(address)
		network := "ip4:icmp"
		listenAddr := "0.0.0.0"
		if ip != nil && ip.To4() == nil {
			network = "ip6:ipv6-icmp"
			listenAddr = "::"
		}
		return net.ListenPacket(network, listenAddr)
	}
	srv.SetDialICMP(dialICMPFn)
	streamSrv.SetDialICMP(dialICMPFn)

	var userCodecs []*server.PlainUDPCodec
	var userReplays []udpReplayRegistry
	inCtx, inCancel := context.WithCancel(context.Background())
	if config.Transport == "stream" || config.Transport == "h1" || config.Transport == "plain-h1" {
		userCodecs = make([]*server.PlainUDPCodec, 0, len(serverUsers))
		for _, u := range serverUsers {
			codec, err := server.NewPlainUDPCodec(u.PSK, config.ServerId)
			if err != nil {
				_ = replays.Close()
				inCancel()
				return nil, fmt.Errorf("init plain-udp codec: %w", err)
			}
			userCodecs = append(userCodecs, codec)
		}
		userReplays = make([]udpReplayRegistry, len(serverUsers))
		for i := range userReplays {
			userReplays[i].cache = replays
			userReplays[i].namespace = server.UDPReplayNamespace(serverUsers[i].PSK, config.ServerId)
			go userReplays[i].run(inCtx)
		}
	}

	var h3Server *http3.Server
	var vconn *virtualPacketConn
	var tcpTLSConfig *tls.Config
	if config.Transport != "stream" && config.Transport != "h1" && config.Transport != "plain-h1" {
		tlsConfig, err := buildServerTLSConfig(config)
		if err != nil {
			_ = replays.Close()
			inCancel()
			return nil, fmt.Errorf("build h3 tls config: %w", err)
		}
		tcpTLSConfig = tlsConfig.Clone()
		tcpTLSConfig.NextProtos = []string{"h2", "http/1.1"}
		vconn = newVirtualPacketConn()
		h3Server = server.NewHTTP3Server(srv, tlsConfig, 0)
		h3Server.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
			return vconn.connectionContext(ctx, conn.RemoteAddr())
		}
		go func() {
			_ = h3Server.Serve(vconn)
		}()
	}

	h := &InboundHandler{
		config:       config,
		users:        serverUsers,
		server:       srv,
		streamServer: streamSrv,
		h3Server:     h3Server,
		vconn:        vconn,
		userCodecs:   userCodecs,
		replays:      replays,
		userReplays:  userReplays,
		dispatcher:   dispatcher,
		dialICMP:     dialICMPFn,
		tcpTLSConfig: tcpTLSConfig,
		ctx:          inCtx,
		cancel:       inCancel,
		httpSlots:    make(chan struct{}, 1024),
	}

	return h, nil
}

func (h *InboundHandler) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP, xnet.Network_UDP}
}

// Requested by the injected Xray UDP worker; other inbound protocols keep
// their upstream buffer size. This includes Plain-UDP encapsulation overhead.
func (h *InboundHandler) UDPPacketBufferSize() int32 { return 65535 }

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.br.Read(p)
}

type singleListener struct {
	conn   net.Conn
	once   sync.Once
	done   chan struct{}
	closed atomic.Bool
}

func (l *singleListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = &closeNotifyConn{
			Conn: l.conn,
			onClose: func() {
				_ = l.Close()
			},
		}
	})
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleListener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.done)
		_ = l.conn.Close()
	}
	return nil
}

func (l *singleListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

type closeNotifyConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *closeNotifyConn) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.Conn.Close()
}

func (h *InboundHandler) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	if network == xnet.Network_UDP {
		return h.handleUDP(ctx, conn, dispatcher)
	}
	if network != xnet.Network_TCP {
		return nil
	}
	defer conn.Close()
	stopCaller := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCaller()
	stopHandler := context.AfterFunc(h.ctx, func() { _ = conn.Close() })
	defer stopHandler()

	if h.config.Transport == "stream" {
		h.streamServer.HandleConnContext(ctx, conn)
		return nil
	}
	// Bound non-RawStream carrier processing, including incomplete unauthenticated
	// HTTP requests. Authenticated carriers release this slot on connection close.
	if h.httpSlots != nil {
		select {
		case h.httpSlots <- struct{}{}:
			defer func() { <-h.httpSlots }()
		default:
			return fmt.Errorf("chitanda: HTTP carrier limit reached")
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	prefix, err := br.Peek(4)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})

	bconn := &bufferedConn{Conn: conn, br: br}

	if len(prefix) > 0 && prefix[0] == 0x16 && h.tcpTLSConfig != nil {
		tlsConn := tls.Server(bconn, h.tcpTLSConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return err
		}
		state := tlsConn.ConnectionState()
		if state.NegotiatedProtocol == "h2" {
			h2Server := newInboundH2Server()
			h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
				Handler: h.server,
				Context: ctx,
			})
			return nil
		}
		sl := &singleListener{conn: tlsConn, done: make(chan struct{})}
		httpServer := &http.Server{
			Handler:           h.server,
			BaseContext:       func(net.Listener) context.Context { return ctx },
			ReadHeaderTimeout: 2 * time.Second,
			MaxHeaderBytes:    16 << 10,
			IdleTimeout:       30 * time.Second,
		}
		go func() {
			select {
			case <-ctx.Done():
				_ = sl.Close()
			case <-h.ctx.Done():
				_ = sl.Close()
			case <-sl.done:
			}
		}()
		return httpServer.Serve(sl)
	}

	if string(prefix) == "PRI " {
		// HTTP/2 Connection Preface
		h2Server := newInboundH2Server()
		h2Server.ServeConn(bconn, &http2.ServeConnOpts{
			Handler: h.server,
			Context: ctx,
		})
		return nil
	}

	// HTTP/1.x
	sl := &singleListener{conn: bconn, done: make(chan struct{})}
	httpServer := &http.Server{
		Handler:           h.server,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 2 * time.Second,
		MaxHeaderBytes:    16 << 10,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		select {
		case <-ctx.Done():
			_ = sl.Close()
		case <-h.ctx.Done():
			_ = sl.Close()
		case <-sl.done:
		}
	}()

	return httpServer.Serve(sl)
}

func newInboundH2Server() *http2.Server {
	// Match the standalone server's flow-control budget. The default
	// stream window caps a single upload to roughly one window per RTT.
	return &http2.Server{
		MaxUploadBufferPerConnection: 64 * 1024 * 1024,
		MaxUploadBufferPerStream:     32 * 1024 * 1024,
		MaxReadFrameSize:             1 << 20,
		IdleTimeout:                  3 * time.Minute,
	}
}

func (h *InboundHandler) handleUDP(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher) error {
	defer conn.Close()
	stopCaller := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCaller()
	if h.ctx != nil {
		stopHandler := context.AfterFunc(h.ctx, func() { _ = conn.Close() })
		defer stopHandler()
	}

	// 1. HTTP/3 UDP path for h2, h3, and auto inbounds (QUIC Datagrams).
	// Directly routes to QUIC stack with 0 µs Plain-UDP trial decryption overhead.
	if h.vconn != nil {
		key := conn.RemoteAddr().String()
		h.vconn.registerConn(key, conn, ctx)
		defer h.vconn.unregisterConn(key, conn)

		reader := newFullPacketReader(conn)
		for {
			packets, readErr := reader.ReadMultiBuffer()
			h.feedH3Packets(packets, conn.RemoteAddr())
			if readErr != nil {
				return readErr
			}
		}
	}

	// 2. Native Plain-UDP path for stream, h1, and plain-h1 inbounds.
	userCodecs := h.userCodecs
	userReplays := h.userReplays
	if len(userCodecs) != len(userReplays) || len(userCodecs) == 0 {
		return fmt.Errorf("chitanda: plain-udp not initialized for transport %q", h.config.Transport)
	}

	routes := newUDPRoutes(ctx, dispatcher, userCodecs, conn, h.dialICMP)
	defer routes.Close()

	reader := newFullPacketReader(conn)
	for {
		packets, readErr := reader.ReadMultiBuffer()
		h.forwardPlainUDPPackets(ctx, routes, packets)
		if readErr != nil {
			return readErr
		}
	}
}

// A Reader may return both data and an error. Consume/release the whole batch
// before the caller handles that error, including EOF on the final packet.
func (h *InboundHandler) feedH3Packets(packets buf.MultiBuffer, remote net.Addr) {
	defer buf.ReleaseMulti(packets)
	for _, packet := range packets {
		if packet != nil && isQUICPacket(packet.Bytes()) {
			h.vconn.feed(packet.Bytes(), remote)
		}
	}
}

func (h *InboundHandler) forwardPlainUDPPackets(ctx context.Context, routes *udpRoutes, packets buf.MultiBuffer) {
	defer buf.ReleaseMulti(packets)
	for i, packet := range packets {
		if packet == nil {
			continue
		}
		if packet.IsEmpty() {
			packet.Release()
			packets[i] = nil
			continue
		}
		now := time.Now()
		matchedIdx, sessionID, targetAddr, rawData, timestamp, seq, err := server.DecodeClientPacketMulti(h.userCodecs, packet.Bytes(), now)
		// The decoder returns an owned plaintext copy. Release the outer
		// ciphertext before any potentially blocking routing/target write.
		packet.Release()
		packets[i] = nil
		if err != nil || matchedIdx < 0 || matchedIdx >= len(h.userReplays) || !h.userReplays[matchedIdx].accept(sessionID, seq, now, timestamp) {
			continue
		}

		if strings.HasPrefix(targetAddr, "icmp:") {
			_ = routes.WriteICMP(ctx, matchedIdx, sessionID, targetAddr, rawData)
			continue
		}

		dest, err := xnet.ParseDestination("udp:" + targetAddr)
		if err != nil {
			continue
		}

		copyInbound := session.Inbound{Tag: "chitanda-inbound"}
		if inbound := session.InboundFromContext(ctx); inbound != nil {
			copyInbound = *inbound
			if copyInbound.Tag == "" {
				copyInbound.Tag = "chitanda-inbound"
			}
		}
		if matchedIdx < len(h.users) && h.users[matchedIdx].Email != "" {
			copyInbound.User = &protocol.MemoryUser{Email: h.users[matchedIdx].Email, Level: h.users[matchedIdx].Level}
		}
		packetCtx := session.ContextWithInbound(ctx, &copyInbound)
		_ = routes.Write(packetCtx, matchedIdx, sessionID, dest, rawData)
	}
}

func (h *InboundHandler) Close() error {
	h.closeOnce.Do(func() {
		h.cancel()
		if h.h3Server != nil {
			_ = h.h3Server.Close()
		}
		if h.vconn != nil {
			_ = h.vconn.Close()
		}
		if h.streamServer != nil {
			// StreamServer owns this handler's replay reference and releases
			// it on Close. Releasing it again would close a peer inbound's
			// shared cache while that inbound is still serving requests.
			_ = h.streamServer.Close()
		} else if h.replays != nil {
			_ = h.replays.Close()
		}
	})
	return nil
}

type pipeConn struct {
	reader     *buf.BufferedReader
	readCloser interface{}
	reads      *connio.Reader
	writes     *pipeWriteQueue
}

var pipeReadPool = sync.Pool{New: func() any { b := make([]byte, 64<<10); return &b }}

func newPipeConn(reader buf.Reader, writer buf.Writer) *pipeConn {
	c := &pipeConn{
		readCloser: reader,
		writes:     newPipeWriteQueue(writer),
	}
	if reader != nil {
		c.reader = &buf.BufferedReader{Reader: reader}
		c.reads = connio.NewOwnedReader(func() ([]byte, net.Addr, func(), error) {
			b := pipeReadPool.Get().(*[]byte)
			n, err := c.reader.Read(*b)
			return (*b)[:n], nil, func() { pipeReadPool.Put(b) }, err
		}, func() error { _ = common.Interrupt(reader); return common.Close(reader) })
	}
	return c
}

func (c *pipeConn) Read(b []byte) (n int, err error) {
	if c.reads == nil {
		return 0, io.EOF
	}
	return c.reads.Read(b)
}

func (c *pipeConn) Write(b []byte) (n int, err error) {
	return c.writes.Write(b)
}

func (c *pipeConn) Close() error {
	err1 := c.writes.Close()
	var err2 error
	if c.reads != nil {
		err2 = c.reads.Close()
	} else if c.readCloser != nil {
		_ = common.Interrupt(c.readCloser)
		err2 = common.Close(c.readCloser)
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *pipeConn) CloseWrite() error {
	return c.writes.CloseWrite()
}

func (c *pipeConn) CloseRead() error {
	if c.reads != nil {
		return c.reads.Close()
	}
	if c.readCloser != nil {
		_ = common.Interrupt(c.readCloser)
		return common.Close(c.readCloser)
	}
	return nil
}

func (c *pipeConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *pipeConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }

func (c *pipeConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *pipeConn) SetReadDeadline(t time.Time) error {
	if c.reads != nil {
		return c.reads.SetDeadline(t)
	}
	return nil
}

func (c *pipeConn) SetWriteDeadline(t time.Time) error {
	return c.writes.SetDeadline(t)
}

func isQUICPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	// Fixed bit (bit 6 of byte 0) must be 1 in QUIC (RFC 9000 section 17)
	if (data[0] & 0x40) == 0 {
		return false
	}
	return true
}

func buildServerTLSConfig(config *InboundConfig) (*tls.Config, error) {
	if config.CertFile == "" || config.KeyFile == "" {
		return nil, fmt.Errorf("H3 requires cert_file and key_file (or an inherited streamSettings.tlsSettings file pair)")
	}
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load x509 keypair: %w", err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{http3.NextProtoH3},
	}
	// Go TLS generates independent server-only ticket keys and rotates them.
	if config.StrictSni != "" {
		tlsConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if !strings.EqualFold(chi.ServerName, config.StrictSni) {
				return nil, fmt.Errorf("strict SNI mismatch: got %q, want %q", chi.ServerName, config.StrictSni)
			}
			return nil, nil
		}
	}
	return tlsConfig, nil
}

type packetItem struct {
	data []byte
	addr net.Addr
}

var virtualQueuedBytes atomic.Int64

func reserveVirtualBytes(size int64) bool {
	for {
		used := virtualQueuedBytes.Load()
		if size > (64<<20)-used {
			return false
		}
		if virtualQueuedBytes.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

type virtualPacketConn struct {
	recvCh    chan *packetItem
	closeCh   chan struct{}
	closed    atomic.Bool
	onFeed    func() // test hook; nil in production to avoid atomic overhead
	localAddr net.Addr

	mu            sync.RWMutex
	writers       map[string]stat.Connection
	writeHelpers  map[string]*connio.Writer
	writeDeadline time.Time
	feedMu        sync.Mutex
	queuedBytes   atomic.Int64
	feedDrops     atomic.Uint64

	deadlineMu      sync.Mutex
	readDeadline    time.Time
	deadlineChanged chan struct{}
	contexts        map[string]context.Context
}

func newVirtualPacketConn() *virtualPacketConn {
	return &virtualPacketConn{
		recvCh:          make(chan *packetItem, 8192),
		closeCh:         make(chan struct{}),
		localAddr:       &net.UDPAddr{IP: net.IPv4zero, Port: 0},
		writers:         make(map[string]stat.Connection),
		writeHelpers:    make(map[string]*connio.Writer),
		contexts:        make(map[string]context.Context),
		deadlineChanged: make(chan struct{}),
	}
}

func (c *virtualPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if c.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		c.deadlineMu.Lock()
		dl, changed := c.readDeadline, c.deadlineChanged
		c.deadlineMu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			if !time.Now().Before(dl) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(dl))
			timeout = timer.C
		}
		select {
		case pkt := <-c.recvCh:
			cost := int64(len(pkt.data) + 64)
			c.queuedBytes.Add(-cost)
			virtualQueuedBytes.Add(-cost)
			if timer != nil {
				timer.Stop()
			}
			return copy(p, pkt.data), pkt.addr, nil
		case <-c.closeCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			// Re-check under the next iteration in case the deadline was extended.
		}
	}
}

func (c *virtualPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if addr == nil {
		return 0, net.InvalidAddrError("nil UDP peer")
	}
	c.mu.RLock()
	writer, ok := c.writeHelpers[addr.String()]
	c.mu.RUnlock()
	if !ok || writer == nil {
		return 0, fmt.Errorf("no active connection for %s", addr.String())
	}
	return writer.WritePacket(p, addr)
}

func (c *virtualPacketConn) Close() error {
	c.feedMu.Lock()
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
		for {
			select {
			case pkt := <-c.recvCh:
				cost := int64(len(pkt.data) + 64)
				c.queuedBytes.Add(-cost)
				virtualQueuedBytes.Add(-cost)
			default:
				goto drained
			}
		}
	}
drained:
	c.feedMu.Unlock()
	c.mu.RLock()
	writers := make([]*connio.Writer, 0, len(c.writeHelpers))
	for _, writer := range c.writeHelpers {
		writers = append(writers, writer)
	}
	c.mu.RUnlock()
	for _, writer := range writers {
		_ = writer.Close()
	}
	return nil
}

func (c *virtualPacketConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *virtualPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *virtualPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
	c.deadlineMu.Unlock()
	return nil
}

func (c *virtualPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	for _, writer := range c.writeHelpers {
		_ = writer.SetDeadline(t)
	}
	return nil
}

func (c *virtualPacketConn) feed(data []byte, addr net.Addr) {
	c.feedMu.Lock()
	defer c.feedMu.Unlock()
	if c.closed.Load() {
		return
	}
	if c.onFeed != nil {
		c.onFeed()
	}
	cost := int64(len(data) + 64)
	if cost > (16<<20)-c.queuedBytes.Load() || !reserveVirtualBytes(cost) {
		c.feedDrops.Add(1)
		return
	}
	c.queuedBytes.Add(cost)
	buf := make([]byte, len(data))
	copy(buf, data)
	select {
	case c.recvCh <- &packetItem{data: buf, addr: addr}:
	default:
		c.queuedBytes.Add(-cost)
		virtualQueuedBytes.Add(-cost)
		c.feedDrops.Add(1)
	}
}

func (c *virtualPacketConn) receiveQueueStats() (int64, uint64) {
	return c.queuedBytes.Load(), c.feedDrops.Load()
}

func (c *virtualPacketConn) registerConn(key string, conn stat.Connection, contexts ...context.Context) {
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		_ = conn.Close()
		return
	}
	old := c.writeHelpers[key]
	if c.writers[key] == conn {
		if len(contexts) > 0 {
			c.contexts[key] = context.WithoutCancel(contexts[0])
		}
		c.mu.Unlock()
		return
	}
	writer := connio.NewWriter(func(p []byte, _ net.Addr) (int, error) { return conn.Write(p) }, nil, conn.Close)
	_ = writer.SetDeadline(c.writeDeadline)
	c.writeHelpers[key] = writer
	c.writers[key] = conn
	if len(contexts) > 0 {
		c.contexts[key] = context.WithoutCancel(contexts[0])
	}
	c.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

func (c *virtualPacketConn) unregisterConn(key string, conn stat.Connection) {
	c.mu.Lock()
	var writer *connio.Writer
	if c.writers[key] == conn {
		writer = c.writeHelpers[key]
		delete(c.writeHelpers, key)
		delete(c.writers, key)
		delete(c.contexts, key)
	}
	c.mu.Unlock()
	if writer != nil {
		_ = writer.Close()
	}
}

type inboundValueContext struct {
	context.Context
	values context.Context
}

func (c inboundValueContext) Value(key any) any {
	if v := c.Context.Value(key); v != nil {
		return v
	}
	return c.values.Value(key)
}

func (c *virtualPacketConn) connectionContext(ctx context.Context, addr net.Addr) context.Context {
	c.mu.RLock()
	values := c.contexts[addr.String()]
	c.mu.RUnlock()
	if values == nil {
		return ctx
	}
	// Keep QUIC's lifetime but preserve the original Xray inbound tag, user and
	// routing metadata even when a short-lived UDP association is replaced.
	return inboundValueContext{Context: ctx, values: values}
}

func init() {
	common.Must(common.RegisterConfig((*InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewInboundHandler(ctx, config.(*InboundConfig))
	}))
}
