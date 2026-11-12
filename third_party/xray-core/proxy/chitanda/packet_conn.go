package chitanda

import (
	"github.com/violetaini/chitanda/pkg/connio"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"io"
	"net"
	"sync"
	"time"
)

// packetAddress keeps domain destinations intact; resolution belongs to Xray's
// configured router/outbound, not the host's default DNS resolver.
type packetAddress string

func (packetAddress) Network() string  { return "udp" }
func (a packetAddress) String() string { return string(a) }

func ownedDatagram(p []byte) *buf.Buffer {
	b := buf.NewWithSize(int32(max(1, len(p))))
	copy(b.Extend(int32(len(p))), p)
	return b
}

type fullPacketReader struct {
	r      io.Reader
	buffer [65535]byte
}

func newFullPacketReader(r io.Reader) buf.Reader {
	if reader, ok := r.(buf.Reader); ok {
		return reader
	}
	return &fullPacketReader{r: r}
}
func (r *fullPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	n, err := r.r.Read(r.buffer[:])
	if err != nil && n == 0 {
		return nil, err
	}
	return buf.MultiBuffer{ownedDatagram(r.buffer[:n])}, err
}

// packetLinkConn preserves one Buffer per UDP packet (unlike BufferedReader and
// MergeBytes, which intentionally flatten/split TCP streams).
type packetLinkConn struct {
	packetReader buf.Reader
	packetWriter buf.Writer
	readMu       sync.Mutex
	pending      buf.MultiBuffer
	readErr      error
	remote       net.Addr
	packetReads  *connio.Reader
	writes       *pipeWriteQueue
}

func newPacketLinkConn(r buf.Reader, w buf.Writer, remote net.Addr) *packetLinkConn {
	c := &packetLinkConn{packetReader: r, packetWriter: w, remote: remote}
	c.packetReads = connio.NewOwnedReader(c.readPacketOwned, func() error { _ = common.Interrupt(r); return common.Close(r) })
	c.writes = newPipeWriteQueue(w)
	return c
}

func (c *packetLinkConn) WriteBatch(payloads [][]byte) error {
	_, err := c.writes.WriteDatagrams(payloads)
	return err
}

func (c *packetLinkConn) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *packetLinkConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.packetReads.ReadPacket(p)
}

func (c *packetLinkConn) readPacketOwned() ([]byte, net.Addr, func(), error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.pending) == 0 {
		if c.readErr != nil {
			return nil, nil, nil, c.readErr
		}
		c.pending, c.readErr = c.packetReader.ReadMultiBuffer()
	}
	b := c.pending[0]
	c.pending[0] = nil
	c.pending = c.pending[1:]
	if b.Len() > 65535 {
		b.Release()
		return nil, nil, nil, io.ErrShortBuffer
	}
	addr := c.remote
	if b.UDP != nil && b.UDP.IsValid() {
		addr = packetAddress(b.UDP.NetAddr())
	}
	// buf.Reader transfers ownership. Keep its Buffer leased until connio has
	// copied this datagram (or discards it on short read/close), not a second
	// payload-sized allocation while the original buffer is already owned.
	return b.Bytes(), addr, b.Release, nil
}

func (c *packetLinkConn) Write(p []byte) (int, error) {
	if len(p) > 65535 {
		return 0, io.ErrShortBuffer
	}
	return c.writes.WriteDatagrams([][]byte{p})
}

func (c *packetLinkConn) Close() error {
	err := c.writes.Close()
	_ = c.packetReads.Close()
	c.readMu.Lock()
	c.pending = buf.ReleaseMulti(c.pending)
	c.readErr = net.ErrClosed
	c.readMu.Unlock()
	return err
}

func (c *packetLinkConn) RemoteAddr() net.Addr               { return c.remote }
func (c *packetLinkConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *packetLinkConn) CloseWrite() error                  { return c.writes.CloseWrite() }
func (c *packetLinkConn) CloseRead() error                   { return c.packetReads.Close() }
func (c *packetLinkConn) SetReadDeadline(t time.Time) error  { return c.packetReads.SetDeadline(t) }
func (c *packetLinkConn) SetWriteDeadline(t time.Time) error { return c.writes.SetDeadline(t) }
func (c *packetLinkConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

// connectedPacketConn is only for the outer tunnel's single configured server.
type connectedPacketConn struct {
	net.Conn
	packets *packetLinkConn
	remote  net.Addr
}

func (c *connectedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.packets.Read(p)
	return n, c.remote, err
}
func (c *connectedPacketConn) Close() error {
	err := c.Conn.Close()
	_ = c.packets.Close()
	return err
}
func (c *connectedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil || addr.String() != c.remote.String() {
		return 0, net.InvalidAddrError("unexpected UDP peer")
	}
	return c.packets.Write(p)
}
func (c *connectedPacketConn) SetReadDeadline(t time.Time) error { return c.packets.SetReadDeadline(t) }
func (c *connectedPacketConn) SetWriteDeadline(t time.Time) error {
	return c.packets.SetWriteDeadline(t)
}
func (c *connectedPacketConn) SetDeadline(t time.Time) error { return c.packets.SetDeadline(t) }
