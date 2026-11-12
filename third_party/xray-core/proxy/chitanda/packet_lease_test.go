package chitanda

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type packetLeaseReader struct {
	mu      sync.Mutex
	packets buf.MultiBuffer
	err     error
}

func (r *packetLeaseReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	packets := r.packets
	r.packets = nil
	return packets, r.err
}

func (r *packetLeaseReader) Close() error {
	r.mu.Lock()
	r.packets = buf.ReleaseMulti(r.packets)
	r.mu.Unlock()
	return nil
}

func TestPacketReadLeaseRetainsBufferUntilRelease(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 1200)
	b := ownedDatagram(payload)
	c := newPacketLinkConn(&packetLeaseReader{packets: buf.MultiBuffer{b}, err: io.EOF}, nil, packetAddress("192.0.2.1:53"))
	defer c.Close()
	data, addr, release, err := c.readPacketOwned()
	if release != nil {
		defer release()
	}
	if err != nil || release == nil || b.Len() != 1200 || addr.String() != "192.0.2.1:53" {
		t.Fatal("buffer released before consumption", b.Len(), addr, err)
	}
	if &data[0] != &b.Bytes()[0] || !bytes.Equal(data, payload) {
		t.Fatal("read copied the already owned payload instead of leasing it")
	}
	release()
	if b.Len() != 0 {
		t.Fatal("completed lease did not recycle its buffer")
	}
}

func TestPacketReadLeaseShortBufferAndTerminalBatch(t *testing.T) {
	for _, terminal := range []error{io.EOF, io.ErrUnexpectedEOF} {
		first, second, empty := ownedDatagram([]byte("discard")), ownedDatagram(bytes.Repeat([]byte{9}, 9000)), ownedDatagram(nil)
		c := newPacketLinkConn(&packetLeaseReader{packets: buf.MultiBuffer{first, second, empty}, err: terminal}, nil, packetAddress("example.test:53"))
		if _, _, err := c.ReadFrom(make([]byte, 2)); !errors.Is(err, io.ErrShortBuffer) {
			t.Fatal("short datagram read", err)
		}
		if first.Len() != 0 {
			t.Fatal("discarded datagram lease was retained")
		}
		out := make([]byte, 9000)
		if n, from, err := c.ReadFrom(out); err != nil || n != 9000 || from.String() != "example.test:53" || !bytes.Equal(out, bytes.Repeat([]byte{9}, 9000)) {
			t.Fatal("data+terminal batch lost its remaining packet", n, from, err)
		}
		if n, _, err := c.ReadFrom(out); n != 0 || err != nil {
			t.Fatal("zero length datagram was lost", n, err)
		}
		if _, _, err := c.ReadFrom(out); !errors.Is(err, terminal) {
			t.Fatal("terminal error was changed", err)
		}
		_ = c.Close()
		if first.Len() != 0 || second.Len() != 0 || empty.Len() != 0 {
			t.Fatal("terminal batch retained an owned buffer")
		}
	}
}

func TestPacketReadLeaseDeadlineAndCloseDrain(t *testing.T) {
	first, second := ownedDatagram([]byte("one")), ownedDatagram([]byte("two"))
	c := newPacketLinkConn(&packetLeaseReader{packets: buf.MultiBuffer{first, second}, err: io.EOF}, nil, packetAddress("192.0.2.1:53"))
	_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := c.ReadFrom(make([]byte, 16)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("expired deadline ignored", err)
	}
	_ = c.Close()
	if first.Len() != 0 || second.Len() != 0 {
		t.Fatal("close retained a prefetched datagram")
	}
}
