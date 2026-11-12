package chitanda

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/server"
	xdispatcher "github.com/xtls/xray-core/app/dispatcher"
	xpolicy "github.com/xtls/xray-core/app/policy"
	xstats "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type multiUserUDPConn struct {
	net.Conn
	data   []byte
	closed chan struct{}
	once   sync.Once
}

func newMultiUserUDPConn(c net.Conn, data []byte) *multiUserUDPConn {
	return &multiUserUDPConn{
		Conn:   c,
		data:   data,
		closed: make(chan struct{}),
	}
}

func (c *multiUserUDPConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if c.data != nil {
		b := buf.FromBytes(c.data)
		c.data = nil
		return buf.MultiBuffer{b}, nil
	}
	<-c.closed
	return nil, io.EOF
}

func (c *multiUserUDPConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return c.Conn.Close()
}

func TestXrayInboundMultiUserHTTP(t *testing.T) {
	aliceKey := []byte("alice-key-at-least-32-bytes-long!")
	bobKey := []byte("bob---key-at-least-32-bytes-long!")

	var mu sync.Mutex
	var dispatchedUsers []*protocol.MemoryUser

	d := &mockTestDispatcher{
		dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
			inbound := session.InboundFromContext(ctx)
			mu.Lock()
			if inbound != nil && inbound.User != nil {
				dispatchedUsers = append(dispatchedUsers, inbound.User)
			}
			mu.Unlock()
			return nil, errors.New("test: destination reached")
		},
	}

	cfg := &InboundConfig{
		Path:      "/api/sync",
		Transport: "h2",
		Users: []*User{
			{Email: "alice@chitanda.org", Psk: string(aliceKey), Level: 1},
			{Email: "bob@chitanda.org", Psk: string(bobKey), Level: 2},
		},
	}

	h, err := newTestInboundHandler(t, newTestContextWithDispatcher(t, d), cfg)
	if err != nil {
		t.Fatalf("newTestInboundHandler: %v", err)
	}
	defer h.Close()

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	ctx = session.ContextWithContent(ctx, &session.Content{})

	// 1. Request as Alice
	{
		target := "1.1.1.1:80"
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := "alice-nonce-1"
		sig := auth.Signature(aliceKey, "tcp-v2", http.MethodPost, "/api/sync", target, ts, nonce)

		req := httptest.NewRequest(http.MethodPost, "https://localhost/api/sync", nil).WithContext(ctx)
		req.ProtoMajor = 2
		req.Header.Set("X-Session-Target", target)
		req.Header.Set("X-Session-Time", ts)
		req.Header.Set("X-Session-Nonce", nonce)
		req.Header.Set("X-Session-Mode", "tcp-v2")
		req.Header.Set("X-Session-Auth", sig)

		w := httptest.NewRecorder()
		h.server.ServeHTTP(w, req)
	}

	// 2. Request as Bob
	{
		target := "2.2.2.2:80"
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := "bob-nonce-1"
		sig := auth.Signature(bobKey, "tcp-v2", http.MethodPost, "/api/sync", target, ts, nonce)

		req := httptest.NewRequest(http.MethodPost, "https://localhost/api/sync", nil).WithContext(ctx)
		req.ProtoMajor = 2
		req.Header.Set("X-Session-Target", target)
		req.Header.Set("X-Session-Time", ts)
		req.Header.Set("X-Session-Nonce", nonce)
		req.Header.Set("X-Session-Mode", "tcp-v2")
		req.Header.Set("X-Session-Auth", sig)

		w := httptest.NewRecorder()
		h.server.ServeHTTP(w, req)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dispatchedUsers) != 2 {
		t.Fatalf("expected 2 dispatched users, got %d", len(dispatchedUsers))
	}
	if dispatchedUsers[0].Email != "alice@chitanda.org" || dispatchedUsers[0].Level != 1 {
		t.Errorf("expected alice@chitanda.org level 1, got %+v", dispatchedUsers[0])
	}
	if dispatchedUsers[1].Email != "bob@chitanda.org" || dispatchedUsers[1].Level != 2 {
		t.Errorf("expected bob@chitanda.org level 2, got %+v", dispatchedUsers[1])
	}
}

func TestXrayInboundMultiUserH3AndAuto(t *testing.T) {
	users := []struct {
		email string
		key   []byte
	}{
		{"alice", []byte("alice-key-at-least-32-bytes-long!")},
		{"bob", []byte("bob---key-at-least-32-bytes-long!")},
	}
	for _, mode := range []string{"h3", "auto"} {
		for _, expected := range users {
			t.Run(mode+"/"+expected.email, func(t *testing.T) {
				serverPacket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer serverPacket.Close()
				clientPacket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer clientPacket.Close()

				identities := make(chan string, 2)
				dispatcher := &mockTestDispatcher{dispatchFn: func(ctx context.Context, _ xnet.Destination) (*transport.Link, error) {
					identity := ""
					if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
						identity = inbound.User.Email
					}
					identities <- identity
					reader, writer := pipe.New()
					return &transport.Link{Reader: reader, Writer: writer}, nil
				}}
				h, err := newTestInboundHandler(t, newTestContextWithDispatcher(t, dispatcher), &InboundConfig{
					Path: "/api/sync", Transport: mode, StrictSni: "localhost",
					Users: []*User{{Email: users[0].email, Psk: string(users[0].key)}, {Email: users[1].email, Psk: string(users[1].key)}},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer h.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				bridge := &reviewUDPBridge{UDPConn: serverPacket, remote: clientPacket.LocalAddr()}
				go func() { _ = h.Process(ctx, xnet.Network_UDP, bridge, dispatcher) }()

				c, err := client.New(client.Config{
					Server: serverPacket.LocalAddr().String(), ServerName: "localhost", Path: "/api/sync",
					PSK: expected.key, TCPTransport: mode, InsecureSkipVerify: true,
					ListenPacket: func(context.Context, string, string) (net.PacketConn, error) { return clientPacket, nil },
				})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				dialCtx, stop := context.WithTimeout(ctx, 8*time.Second)
				defer stop()
				conn, err := c.DialContext(dialCtx, "tcp", "192.0.2.1:443")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := conn.Write([]byte("ping")); err != nil {
					t.Fatal(err)
				}
				var echo [4]byte
				if _, err := io.ReadFull(conn, echo[:]); err != nil || string(echo[:]) != "ping" {
					t.Fatalf("H3 echo=%q err=%v", echo[:], err)
				}
				if got := recvReview(t, identities); got != expected.email {
					t.Fatalf("user=%q, want %q", got, expected.email)
				}
			})
		}
	}
}

func TestXrayInboundMultiUserH3AndAutoConcurrent(t *testing.T) {
	users := []struct {
		email  string
		key    []byte
		target string
	}{
		{"alice", []byte("alice-key-at-least-32-bytes-long!"), "192.0.2.1:443"},
		{"bob", []byte("bob---key-at-least-32-bytes-long!"), "192.0.2.2:443"},
	}
	for _, mode := range []string{"h3", "auto"} {
		t.Run(mode, func(t *testing.T) {
			type event struct{ email, target string }
			events := make(chan event, 4)
			dispatcher := &mockTestDispatcher{dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
				email := ""
				if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.User != nil {
					email = inbound.User.Email
				}
				events <- event{email, dest.NetAddr()}
				reader, writer := pipe.New()
				return &transport.Link{Reader: reader, Writer: writer}, nil
			}}
			h, err := newTestInboundHandler(t, newTestContextWithDispatcher(t, dispatcher), &InboundConfig{
				Path: "/api/sync", Transport: mode, StrictSni: "localhost",
				Users: []*User{{Email: users[0].email, Psk: string(users[0].key)}, {Email: users[1].email, Psk: string(users[1].key)}},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			clients := make([]*client.Client, len(users))
			for i, user := range users {
				serverPacket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer serverPacket.Close()
				clientPacket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer clientPacket.Close()
				bridge := &reviewUDPBridge{UDPConn: serverPacket, remote: clientPacket.LocalAddr()}
				go func() { _ = h.Process(ctx, xnet.Network_UDP, bridge, dispatcher) }()
				clients[i], err = client.New(client.Config{
					Server: serverPacket.LocalAddr().String(), ServerName: "localhost", Path: "/api/sync",
					PSK: user.key, TCPTransport: mode, InsecureSkipVerify: true,
					ListenPacket: func(context.Context, string, string) (net.PacketConn, error) { return clientPacket, nil },
				})
				if err != nil {
					t.Fatal(err)
				}
				defer clients[i].Close()
			}

			var wg sync.WaitGroup
			failures := make(chan error, len(users))
			for i, user := range users {
				wg.Add(1)
				go func(c *client.Client, user struct {
					email  string
					key    []byte
					target string
				}) {
					defer wg.Done()
					dialCtx, stop := context.WithTimeout(ctx, 8*time.Second)
					defer stop()
					conn, err := c.DialContext(dialCtx, "tcp", user.target)
					if err != nil {
						failures <- fmt.Errorf("%s dial: %w", user.email, err)
						return
					}
					defer conn.Close()
					_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
					if _, err := conn.Write([]byte(user.email)); err != nil {
						failures <- fmt.Errorf("%s write: %w", user.email, err)
						return
					}
					echo := make([]byte, len(user.email))
					if _, err := io.ReadFull(conn, echo); err != nil {
						failures <- fmt.Errorf("%s read: %w", user.email, err)
						return
					}
					if string(echo) != user.email {
						failures <- fmt.Errorf("%s echo mismatch: %q", user.email, echo)
					}
				}(clients[i], user)
			}
			wg.Wait()
			close(failures)
			for err := range failures {
				t.Error(err)
			}
			if t.Failed() {
				return
			}
			seen := make(map[string]string)
			for range users {
				e := recvReview(t, events)
				seen[e.target] = e.email
			}
			for _, user := range users {
				if got := seen[user.target]; got != user.email {
					t.Errorf("target %s attributed to %q, want %q", user.target, got, user.email)
				}
			}
		})
	}
}

func TestXrayInboundRejectsInvalidMultiUserProto(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef"
	for name, cfg := range map[string]*InboundConfig{
		"nil config":          nil,
		"missing credentials": {Transport: "stream"},
		"mixed credentials":   {Transport: "stream", Psk: key, Users: []*User{{Email: "alice", Psk: key}}},
		"nil user":            {Transport: "stream", Users: []*User{nil}},
		"empty email":         {Transport: "stream", Users: []*User{{Psk: key}}},
		"short key":           {Transport: "stream", Users: []*User{{Email: "alice", Psk: "short"}}},
		"duplicate key":       {Transport: "stream", Users: []*User{{Email: "alice", Psk: key}, {Email: "bob", Psk: key}}},
	} {
		t.Run(name, func(t *testing.T) {
			if h, err := NewInboundHandler(context.Background(), cfg); err == nil {
				_ = h.Close()
				t.Fatal("invalid protobuf config was accepted")
			}
		})
	}
}

func TestXrayMultiUserStatsPolicy(t *testing.T) {
	policy, err := xpolicy.New(context.Background(), &xpolicy.Config{Level: map[uint32]*xpolicy.Policy{
		1: {Stats: &xpolicy.Policy_Stats{UserUplink: true, UserDownlink: true}},
		2: {Stats: &xpolicy.Policy_Stats{UserUplink: true, UserDownlink: true}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := xstats.NewManager(context.Background(), &xstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		email string
		level uint32
		up    string
		down  string
	}{{"alice", 1, "alice upload", "alice download"}, {"bob", 2, "bob upload upload", "bob download download"}} {
		ctx := session.ContextWithInbound(context.Background(), &session.Inbound{User: &protocol.MemoryUser{Email: tc.email, Level: tc.level}})
		ctx = requestContext(ctx)
		upReader, upWriter := pipe.New()
		downReader, downWriter := pipe.New()
		link := xdispatcher.WrapLink(ctx, policy, manager, &transport.Link{Reader: upReader, Writer: downWriter})
		writeDone := make(chan error, 1)
		go func() { writeDone <- upWriter.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte(tc.up))}) }()
		mb, err := link.Reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		buf.ReleaseMulti(mb)
		if err := <-writeDone; err != nil {
			t.Fatal(err)
		}
		go func() { writeDone <- link.Writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte(tc.down))}) }()
		mb, err = downReader.ReadMultiBuffer()
		if err != nil {
			t.Fatal(err)
		}
		buf.ReleaseMulti(mb)
		if err := <-writeDone; err != nil {
			t.Fatal(err)
		}
		upReader.Interrupt()
		_ = upWriter.Close()
		downReader.Interrupt()
		_ = downWriter.Close()
	}
	for _, tc := range []struct {
		email string
		up    int64
		down  int64
	}{{"alice", int64(len("alice upload")), int64(len("alice download"))}, {"bob", int64(len("bob upload upload")), int64(len("bob download download"))}} {
		for _, direction := range []struct {
			name string
			want int64
		}{{"uplink", tc.up}, {"downlink", tc.down}} {
			name := "user>>>" + tc.email + ">>>traffic>>>" + direction.name
			counter := manager.GetCounter(name)
			if counter == nil || counter.Value() != direction.want {
				t.Fatalf("%s counter = %v, want %d", name, counter, direction.want)
			}
		}
	}
}

func TestXrayInboundMultiUserPlainH1(t *testing.T) {
	aliceKey := []byte("alice-key-at-least-32-bytes-long!")
	bobKey := []byte("bob---key-at-least-32-bytes-long!")

	dispatchedUserCh := make(chan *protocol.MemoryUser, 1)

	d := &mockTestDispatcher{
		dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
			inbound := session.InboundFromContext(ctx)
			if inbound != nil && inbound.User != nil {
				select {
				case dispatchedUserCh <- inbound.User:
				default:
				}
			}
			r, w := pipe.New()
			return &transport.Link{Reader: r, Writer: w}, nil
		},
	}

	cfg := &InboundConfig{
		Path:      "/api/sync",
		Transport: "h1",
		Users: []*User{
			{Email: "alice@chitanda.org", Psk: string(aliceKey), Level: 1},
			{Email: "bob@chitanda.org", Psk: string(bobKey), Level: 2},
		},
	}

	h, err := newTestInboundHandler(t, newTestContextWithDispatcher(t, d), cfg)
	if err != nil {
		t.Fatalf("newTestInboundHandler: %v", err)
	}
	defer h.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h.Process(ctx, xnet.Network_TCP, conn, d)
		}
	}()

	cli, err := client.New(client.Config{
		Server:       ln.Addr().String(),
		PSK:          bobKey,
		Path:         "/api/sync",
		TCPTransport: "h1",
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dcancel()

	conn, err := cli.DialContext(dctx, "tcp", "1.1.1.1:80")
	if err != nil {
		t.Fatalf("DialContext h1: %v", err)
	}
	defer conn.Close()

	select {
	case user := <-dispatchedUserCh:
		if user == nil || user.Email != "bob@chitanda.org" || user.Level != 2 {
			t.Fatalf("expected bob dispatched with level 2, got: %+v", user)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bob dispatch in plain-h1")
	}
}

func TestXrayInboundMultiUserStream(t *testing.T) {
	aliceKey := []byte("alice-key-at-least-32-bytes-long!")
	bobKey := []byte("bob---key-at-least-32-bytes-long!")

	dispatchedUserCh := make(chan *protocol.MemoryUser, 1)

	d := &mockTestDispatcher{
		dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
			inbound := session.InboundFromContext(ctx)
			if inbound != nil && inbound.User != nil {
				select {
				case dispatchedUserCh <- inbound.User:
				default:
				}
			}
			r, w := pipe.New()
			return &transport.Link{Reader: r, Writer: w}, nil
		},
	}

	cfg := &InboundConfig{
		ServerId:  "test-srv",
		Transport: "stream",
		Users: []*User{
			{Email: "alice@chitanda.org", Psk: string(aliceKey), Level: 1},
			{Email: "bob@chitanda.org", Psk: string(bobKey), Level: 2},
		},
	}

	h, err := newTestInboundHandler(t, newTestContextWithDispatcher(t, d), cfg)
	if err != nil {
		t.Fatalf("newTestInboundHandler: %v", err)
	}
	defer h.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h.Process(ctx, xnet.Network_TCP, conn, d)
		}
	}()

	cli, err := client.New(client.Config{
		Server:       ln.Addr().String(),
		ServerID:     "test-srv",
		PSK:          aliceKey,
		TCPTransport: "stream",
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	defer cli.Close()

	dctx, dcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dcancel()

	conn, err := cli.DialContext(dctx, "tcp", "2.2.2.2:80")
	if err != nil {
		t.Fatalf("DialContext stream: %v", err)
	}
	defer conn.Close()

	select {
	case user := <-dispatchedUserCh:
		if user == nil || user.Email != "alice@chitanda.org" || user.Level != 1 {
			t.Fatalf("expected alice dispatched with level 1, got: %+v", user)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alice dispatch in stream")
	}
}

func TestXrayInboundMultiUserNativeUDP(t *testing.T) {
	aliceKey := []byte("alice-key-at-least-32-bytes-long!")
	bobKey := []byte("bob---key-at-least-32-bytes-long!")

	aliceCodec, err := server.NewPlainUDPCodec(aliceKey)
	if err != nil {
		t.Fatalf("NewPlainUDPCodec alice: %v", err)
	}
	bobCodec, err := server.NewPlainUDPCodec(bobKey)
	if err != nil {
		t.Fatalf("NewPlainUDPCodec bob: %v", err)
	}

	var mu sync.Mutex
	var lastDispatchedUser *protocol.MemoryUser
	var lastDest xnet.Destination

	d := &mockTestDispatcher{
		dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
			inbound := session.InboundFromContext(ctx)
			mu.Lock()
			if inbound != nil && inbound.User != nil {
				lastDispatchedUser = inbound.User
			}
			lastDest = dest
			mu.Unlock()

			upReader, upWriter := pipe.New(pipe.WithSizeLimit(65535))
			downReader, downWriter := pipe.New(pipe.WithSizeLimit(65535))

			// Echo server response
			go func() {
				mb, err := upReader.ReadMultiBuffer()
				if err == nil {
					_ = downWriter.WriteMultiBuffer(mb)
				}
			}()

			return &transport.Link{
				Reader: downReader,
				Writer: upWriter,
			}, nil
		},
	}

	cfg := &InboundConfig{
		Transport: "stream",
		Users: []*User{
			{Email: "alice@chitanda.org", Psk: string(aliceKey), Level: 1},
			{Email: "bob@chitanda.org", Psk: string(bobKey), Level: 2},
		},
	}

	h, err := newTestInboundHandler(t, newTestContextWithDispatcher(t, d), cfg)
	if err != nil {
		t.Fatalf("newTestInboundHandler: %v", err)
	}
	defer h.Close()

	// 1. Alice sends UDP packet
	now := time.Now()
	alicePkt, err := aliceCodec.EncodeClientPacket(1001, "8.8.8.8:53", []byte("dns-alice"), now)
	if err != nil {
		t.Fatalf("EncodeClientPacket alice: %v", err)
	}

	c1, s1 := net.Pipe()
	s1Conn := newMultiUserUDPConn(s1, bytes.Clone(alicePkt))
	go func() {
		_ = h.handleUDP(context.Background(), s1Conn, d)
	}()

	// Wait for echo on c1
	bufAlice := make([]byte, 65535)
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c1.Read(bufAlice)
	if err != nil {
		t.Fatalf("read echo alice: %v", err)
	}
	_ = s1Conn.Close()
	_ = c1.Close()

	// Verify decrypted response with Alice's codec
	sid, from, respData, _, _, err := aliceCodec.DecodeServerPacket(bufAlice[:n], time.Now())
	if err != nil {
		t.Fatalf("DecodeServerPacket alice failed: %v", err)
	}
	if sid != 1001 || string(respData) != "dns-alice" {
		t.Fatalf("mismatched echo response for alice: sid=%d, from=%s, data=%q", sid, from, respData)
	}

	mu.Lock()
	if lastDispatchedUser == nil || lastDispatchedUser.Email != "alice@chitanda.org" || lastDispatchedUser.Level != 1 {
		t.Fatalf("expected alice dispatched in UDP, got %+v", lastDispatchedUser)
	}
	if lastDest.NetAddr() != "8.8.8.8:53" {
		t.Fatalf("expected dest 8.8.8.8:53, got %s", lastDest.NetAddr())
	}
	mu.Unlock()

	// 2. Bob sends UDP packet
	bobPkt, err := bobCodec.EncodeClientPacket(2002, "1.1.1.1:53", []byte("dns-bob"), now)
	if err != nil {
		t.Fatalf("EncodeClientPacket bob: %v", err)
	}

	c2, s2 := net.Pipe()
	s2Conn := newMultiUserUDPConn(s2, bytes.Clone(bobPkt))
	go func() {
		_ = h.handleUDP(context.Background(), s2Conn, d)
	}()

	// Wait for echo on c2
	bufBob := make([]byte, 65535)
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n2, err := c2.Read(bufBob)
	if err != nil {
		t.Fatalf("read echo bob: %v", err)
	}
	_ = s2Conn.Close()
	_ = c2.Close()

	// Verify decrypted response with Bob's codec
	sid2, from2, respData2, _, _, err := bobCodec.DecodeServerPacket(bufBob[:n2], time.Now())
	if err != nil {
		t.Fatalf("DecodeServerPacket bob failed: %v", err)
	}
	if sid2 != 2002 || string(respData2) != "dns-bob" {
		t.Fatalf("mismatched echo response for bob: sid=%d, from=%s, data=%q", sid2, from2, respData2)
	}

	mu.Lock()
	if lastDispatchedUser == nil || lastDispatchedUser.Email != "bob@chitanda.org" || lastDispatchedUser.Level != 2 {
		t.Fatalf("expected bob dispatched in UDP, got %+v", lastDispatchedUser)
	}
	if lastDest.NetAddr() != "1.1.1.1:53" {
		t.Fatalf("expected dest 1.1.1.1:53, got %s", lastDest.NetAddr())
	}
	mu.Unlock()
}
