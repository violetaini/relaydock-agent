package chitanda

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/server"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type terminalUDPBatchConn struct {
	*mockStatConn
	packets buf.MultiBuffer
	err     error
}

func (c *terminalUDPBatchConn) ReadMultiBuffer() (buf.MultiBuffer, error) {
	packets := c.packets
	c.packets = nil
	return packets, c.err
}

func finalBatchConn(packets buf.MultiBuffer, err error) *terminalUDPBatchConn {
	return &terminalUDPBatchConn{
		mockStatConn: &mockStatConn{
			remoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40101},
			localAddr:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40102},
		},
		packets: packets,
		err:     err,
	}
}

func checkFinalBatchReleased(t *testing.T, refs buf.MultiBuffer) {
	t.Helper()
	for _, packet := range refs {
		if packet != nil && packet.Len() != 0 {
			t.Fatalf("terminal batch buffer not released: len=%d", packet.Len())
		}
	}
}

func TestNativeUDPProcessesDataBeforeTerminalReadError(t *testing.T) {
	for _, readErr := range []error{io.EOF, io.ErrUnexpectedEOF, os.ErrDeadlineExceeded} {
		t.Run(readErr.Error(), func(t *testing.T) {
			var dispatches atomic.Int32
			dispatcher := &mockTestDispatcher{dispatchFn: func(context.Context, xnet.Destination) (*transport.Link, error) {
				dispatches.Add(1)
				r, w := pipe.New()
				return &transport.Link{Reader: r, Writer: w}, nil
			}}
			h, err := newTestInboundHandler(t, newTestContextWithDispatcher(t, dispatcher), &InboundConfig{Psk: string(reviewKey), Path: "/last-batch", Transport: "stream"})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			codec, err := server.NewPlainUDPCodec(reviewKey)
			if err != nil {
				t.Fatal(err)
			}
			packets := buf.MultiBuffer{nil, ownedDatagram(nil), ownedDatagram([]byte("unauthenticated"))}
			for _, target := range []string{"192.0.2.1:53", "192.0.2.2:53"} {
				wire, err := codec.EncodeClientPacket(4321, target, []byte("last datagram"), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				packets = append(packets, ownedDatagram(wire))
			}
			refs := append(buf.MultiBuffer(nil), packets...)
			defer buf.ReleaseMulti(refs)
			conn := finalBatchConn(packets, readErr)
			if err := h.handleUDP(context.Background(), conn, dispatcher); !errors.Is(err, readErr) {
				t.Fatalf("terminal error changed: %v", err)
			}
			if dispatches.Load() != 2 {
				t.Fatalf("valid final datagrams dispatched=%d, want 2", dispatches.Load())
			}
			checkFinalBatchReleased(t, refs)
		})
	}
}

func TestH3UDPFeedsDataBeforeTerminalReadError(t *testing.T) {
	for _, mode := range []string{"h2", "h3", "auto"} {
		for _, readErr := range []error{io.EOF, io.ErrUnexpectedEOF, os.ErrDeadlineExceeded} {
			t.Run(mode+"/"+readErr.Error(), func(t *testing.T) {
				dispatcher := &mockTestDispatcher{dispatchFn: func(context.Context, xnet.Destination) (*transport.Link, error) {
					t.Error("unauthenticated QUIC packet reached dispatcher")
					return nil, errors.New("must not dispatch")
				}}
				h, err := newTestInboundHandler(t, newTestContextWithDispatcher(t, dispatcher), &InboundConfig{Psk: string(reviewKey), Path: "/last-batch", Transport: mode})
				if err != nil {
					t.Fatal(err)
				}
				defer h.Close()
				var fed atomic.Int32
				h.vconn.onFeed = func() { fed.Add(1) }
				packets := buf.MultiBuffer{nil, ownedDatagram(nil), ownedDatagram([]byte("invalid"))}
				for range 2 {
					wire := make([]byte, 1200)
					wire[0] = 0x40
					packets = append(packets, ownedDatagram(wire))
				}
				refs := append(buf.MultiBuffer(nil), packets...)
				defer buf.ReleaseMulti(refs)
				conn := finalBatchConn(packets, readErr)
				if err := h.handleUDP(context.Background(), conn, dispatcher); !errors.Is(err, readErr) {
					t.Fatalf("terminal error changed: %v", err)
				}
				if fed.Load() != 2 {
					t.Fatalf("final QUIC datagrams fed=%d, want 2", fed.Load())
				}
				checkFinalBatchReleased(t, refs)
			})
		}
	}
}
