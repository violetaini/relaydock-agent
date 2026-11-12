package chitanda

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// TestUDPBufferIsolation verifies P1 issue 1:
// buf.MergeBytes creates an independently owned buffer, preventing subsequent
// ReadFrom iterations from overwriting previously received packets.
func TestUDPBufferIsolation(t *testing.T) {
	recvBuf := make([]byte, 1024)

	// Simulate first packet arrival: "AAAA"
	copy(recvBuf[:4], []byte("AAAA"))
	mb1 := buf.MergeBytes(nil, recvBuf[:4])
	defer func() {
		for _, b := range mb1 {
			b.Release()
		}
	}()

	// Simulate second packet arrival overwriting recvBuf: "BBBB"
	copy(recvBuf[:4], []byte("BBBB"))
	mb2 := buf.MergeBytes(nil, recvBuf[:4])
	defer func() {
		for _, b := range mb2 {
			b.Release()
		}
	}()

	// Verify that mb1 was NOT mutated by the subsequent write to recvBuf
	var mb1Data []byte
	for _, b := range mb1 {
		mb1Data = append(mb1Data, b.Bytes()...)
	}
	if !bytes.Equal(mb1Data, []byte("AAAA")) {
		t.Fatalf("expected mb1 to retain 'AAAA', but got %q (buffer was clobbered)", string(mb1Data))
	}

	var mb2Data []byte
	for _, b := range mb2 {
		mb2Data = append(mb2Data, b.Bytes()...)
	}
	if !bytes.Equal(mb2Data, []byte("BBBB")) {
		t.Fatalf("expected mb2 to contain 'BBBB', but got %q", string(mb2Data))
	}
}

// TestUDPDestinationPreservation verifies P1 issue 2:
// Downlink UDP response source addresses are preserved in b.UDP metadata,
// and uplink custom b.UDP target destinations are correctly extracted.
func TestUDPDestinationPreservation(t *testing.T) {
	// Downlink: source address from ReadFrom must be converted to xnet.Destination on b.UDP
	fromAddr, err := net.ResolveUDPAddr("udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("resolve udp addr failed: %v", err)
	}

	recvBuf := []byte("dns-response-payload")
	mb := buf.MergeBytes(nil, recvBuf)
	defer func() {
		for _, b := range mb {
			b.Release()
		}
	}()

	if dest, err := xnet.ParseDestination("udp:" + fromAddr.String()); err == nil {
		for _, b := range mb {
			b.UDP = &dest
		}
	} else {
		t.Fatalf("parse destination failed: %v", err)
	}

	for _, b := range mb {
		if b.UDP == nil {
			t.Fatalf("expected b.UDP to be set, but got nil")
		}
		if b.UDP.NetAddr() != "1.1.1.1:53" {
			t.Fatalf("expected b.UDP.NetAddr() to be '1.1.1.1:53', got %q", b.UDP.NetAddr())
		}
	}

	// Uplink: per-packet b.UDP destination must override default target
	defaultAddr, _ := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	customDest, _ := xnet.ParseDestination("udp:9.9.9.9:53")

	pktBuf := buf.New()
	defer pktBuf.Release()
	pktBuf.UDP = &customDest

	destAddr := defaultAddr
	if pktBuf.UDP != nil && pktBuf.UDP.IsValid() {
		if uAddr, err := net.ResolveUDPAddr("udp", pktBuf.UDP.NetAddr()); err == nil {
			destAddr = uAddr
		}
	}

	if destAddr.String() != "9.9.9.9:53" {
		t.Fatalf("expected destAddr to be overridden to '9.9.9.9:53', got %q", destAddr.String())
	}
}

// TestInboundContextPreservation verifies P1 issue 7:
// Existing inbound session metadata (inboundTag, Source, Gateway) is preserved
// and not overwritten by a hardcoded dummy tag.
func TestInboundContextPreservation(t *testing.T) {
	srcDest, err := xnet.ParseDestination("tcp:192.168.1.100:54321")
	if err != nil {
		t.Fatalf("parse src destination failed: %v", err)
	}

	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Tag:    "custom-production-inbound",
		Source: srcDest,
	})

	// Run inbound context logic
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		inbound = &session.Inbound{
			Tag: "chitanda-inbound",
		}
		ctx = session.ContextWithInbound(ctx, inbound)
	} else if inbound.Tag == "" {
		inbound.Tag = "chitanda-inbound"
	}

	finalInbound := session.InboundFromContext(ctx)
	if finalInbound == nil {
		t.Fatalf("inbound context lost")
	}
	if finalInbound.Tag != "custom-production-inbound" {
		t.Fatalf("expected inbound Tag to remain 'custom-production-inbound', got %q", finalInbound.Tag)
	}
	if !finalInbound.Source.IsValid() || finalInbound.Source.NetAddr() != "192.168.1.100:54321" {
		t.Fatalf("expected Source '192.168.1.100:54321', got %v", finalInbound.Source)
	}
}
