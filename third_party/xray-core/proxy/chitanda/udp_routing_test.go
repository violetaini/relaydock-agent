package chitanda

import (
	"bytes"
	"context"
	"github.com/violetaini/chitanda/pkg/client"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/udp"
	"github.com/xtls/xray-core/transport/pipe"
	"net"
	"testing"
	"time"
)

func TestH3UDPUsesXrayDispatcherAndMetadata(t *testing.T) {
	serverPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverPC.Close()
	clientPC, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer clientPC.Close()
	destinations := make(chan xnet.Destination, 1)
	tags := make(chan string, 1)
	dispatcher := &mockTestDispatcher{dispatchFn: func(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
		destinations <- dest
		in := session.InboundFromContext(ctx)
		if in == nil {
			tags <- "missing"
		} else {
			tags <- in.Tag
		}
		r, w := pipe.New()
		return &transport.Link{Reader: r, Writer: w}, nil
	}}
	h, err := newTestInboundHandler(t, newTestContextWithDispatcher(t, dispatcher), &InboundConfig{Psk: string(reviewKey), Path: "/review", Transport: "h3"})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: "udp-rule-tag"})
	go h.Process(ctx, xnet.Network_UDP, &reviewUDPBridge{UDPConn: serverPC, remote: clientPC.LocalAddr()}, dispatcher)
	c, err := client.New(client.Config{Server: serverPC.LocalAddr().String(), ServerName: "localhost", PSK: reviewKey, Path: "/review", TCPTransport: "h3", InsecureSkipVerify: true, ListenPacket: func(context.Context, string, string) (net.PacketConn, error) { return clientPC, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := c.ListenPacket(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	payload := bytes.Repeat([]byte{42}, 700)
	target := packetAddress("must-not-resolve.invalid:53")
	if _, err = p.WriteTo(payload, target); err != nil {
		t.Fatal(err)
	}
	if dest := recvReview(t, destinations); dest.Network != xnet.Network_UDP || dest.NetAddr() != target.String() {
		t.Fatalf("wrong routed destination: %v", dest)
	}
	if tag := recvReview(t, tags); tag != "udp-rule-tag" {
		t.Fatalf("lost inbound tag: %s", tag)
	}
	p.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 1500)
	n, _, err := p.ReadFrom(b)
	if err != nil || !bytes.Equal(b[:n], payload) {
		t.Fatalf("routed UDP echo: n=%d err=%v", n, err)
	}
}

func TestOutboundUDPCannotBypassXrayDialer(t *testing.T) {
	for _, mode := range []string{"stream", "h3"} {
		t.Run(mode, func(t *testing.T) {
			h, err := NewOutboundHandler(newTestContextWithDispatcher(t, nil), &OutboundConfig{Server: "127.0.0.1:9999", ServerName: "localhost", Psk: string(reviewKey), Path: "/review", Transport: mode, AllowInsecure: true})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			dialer := &reviewDenyDialer{}
			ctx, cancel := context.WithTimeout(withDialer(context.Background(), dialer), time.Second)
			defer cancel()
			p, err := h.client.ListenPacket(ctx)
			if p != nil {
				p.Close()
			}
			if err == nil || dialer.calls.Load() == 0 {
				t.Fatal("UDP bypassed the supplied Xray deny dialer")
			}
		})
	}
}

func TestOptInUDPListenerKeepsLargePackets(t *testing.T) {
	reserve, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := reserve.LocalAddr().(*net.UDPAddr)
	reserve.Close()
	hub, err := udp.ListenUDP(context.Background(), xnet.LocalHostIP, xnet.Port(addr.Port), &internet.MemoryStreamConfig{}, udp.HubPacketSize(65535))
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	sender, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	payload := bytes.Repeat([]byte{19}, 9000)
	if _, err := sender.Write(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-hub.Receive():
		defer packet.Payload.Release()
		if !bytes.Equal(packet.Payload.Bytes(), payload) {
			t.Fatalf("UDP listener truncated 9000 bytes to %d", packet.Payload.Len())
		}
	case <-time.After(time.Second):
		t.Fatal("large datagram not delivered")
	}
}

func TestPacketLinkKeepsLargeBuffersAndOwnership(t *testing.T) {
	r, w := pipe.New()
	conn := newPacketLinkConn(r, w, packetAddress("192.0.2.1:53"))
	defer conn.Close()
	payload := bytes.Repeat([]byte{5}, 9000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	payload[0] = 8
	got := make([]byte, 10000)
	n, err := conn.Read(got)
	if err != nil || n != 9000 || got[0] != 5 {
		t.Fatalf("packet alias/split: %d %v", n, err)
	}
	// The next packet remains a separate packet, not part of the first read.
	if err := w.WriteMultiBuffer(buf.MultiBuffer{ownedDatagram([]byte("one")), ownedDatagram([]byte("two"))}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"one", "two"} {
		n, err := conn.Read(got)
		if err != nil || string(got[:n]) != want {
			t.Fatalf("packet boundary: %q %v", got[:n], err)
		}
	}
}

func TestPacketLinkOwnedReadDoesNotAllocateMaximumUDPPacket(t *testing.T) {
	r, w := pipe.New()
	conn := newPacketLinkConn(r, w, packetAddress("192.0.2.1:53"))
	defer conn.Close()
	if err := w.WriteMultiBuffer(buf.MultiBuffer{ownedDatagram(bytes.Repeat([]byte{7}, 1200))}); err != nil {
		t.Fatal(err)
	}
	packet, _, release, err := conn.readPacketOwned()
	if release != nil {
		defer release()
	}
	if err != nil || len(packet) != 1200 || cap(packet) >= 65535 {
		t.Fatalf("owned UDP packet: length=%d capacity=%d err=%v", len(packet), cap(packet), err)
	}
}
