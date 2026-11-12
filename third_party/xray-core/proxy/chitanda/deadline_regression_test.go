package chitanda

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestVirtualPacketConnExpiredWriteDeadline(t *testing.T) {
	c := newVirtualPacketConn()
	defer c.Close()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	c.registerConn(addr.String(), &mockStatConn{remoteAddr: addr})
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	if n, err := c.WriteTo([]byte("test"), addr); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired write = %d, %v", n, err)
	}
	c.SetWriteDeadline(time.Time{})
	if n, err := c.WriteTo([]byte("test"), addr); n != 4 || err != nil {
		t.Fatalf("reset write = %d, %v", n, err)
	}
}

type blockedVirtualWrite struct {
	mockStatConn
	started chan struct{}
	stop    chan struct{}
	once    sync.Once
}

func (c *blockedVirtualWrite) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	<-c.stop
	return 0, net.ErrClosed
}
func (c *blockedVirtualWrite) Close() error {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
	return nil
}

func TestVirtualPacketConnBlockedWriteDeadlineAndClose(t *testing.T) {
	c := newVirtualPacketConn()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	underlying := &blockedVirtualWrite{started: make(chan struct{}), stop: make(chan struct{})}
	c.registerConn(addr.String(), underlying)
	done := make(chan error, 1)
	go func() { _, err := c.WriteTo([]byte("test"), addr); done <- err }()
	select {
	case <-underlying.started:
	case <-time.After(time.Second):
		t.Fatal("write not started")
	}
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write ignored deadline")
	}
	closed := make(chan struct{})
	go func() { c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close did not abort blocked write")
	}
}

func TestVirtualPacketConnQueueBudgetReleasedOnClose(t *testing.T) {
	before := virtualQueuedBytes.Load()
	c := newVirtualPacketConn()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	for i := 0; i < 600; i++ {
		c.feed(make([]byte, 32<<10), addr)
	}
	bytes, drops := c.receiveQueueStats()
	if bytes > 16<<20 || drops == 0 {
		t.Fatalf("budget ignored: %d/%d", bytes, drops)
	}
	c.Close()
	if virtualQueuedBytes.Load() != before {
		t.Fatal("global receive budget leaked")
	}
}
