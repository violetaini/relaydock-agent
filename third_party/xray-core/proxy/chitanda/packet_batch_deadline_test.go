package chitanda

import (
	"bytes"
	"errors"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
	"io"
	"os"
	"testing"
	"time"
)

func TestRegressionOctober15PacketBatchRespectsWriteDeadline(t *testing.T) {
	r, w := pipe.New()
	c := newPacketLinkConn(nil, w, packetAddress("192.0.2.1:53"))
	defer c.Close()
	defer r.Interrupt()
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := c.Write([]byte("single")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("single write: %v", err)
	}
	err := c.WriteBatch([][]byte{[]byte("batch-a"), []byte("batch-b")})
	if err == nil {
		mb, readErr := r.ReadMultiBufferTimeout(100 * time.Millisecond)
		defer buf.ReleaseMulti(mb)
		t.Fatalf("expired deadline bypassed: batch accepted=%d bytes readErr=%v", mb.Len(), readErr)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("batch error: %v", err)
	}
}

func TestPacketBatchDeadlineRecoveryAndBoundaries(t *testing.T) {
	r, w := pipe.New(pipe.WithSizeLimit(0))
	defer r.Interrupt()
	if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("occupied"))}); err != nil {
		t.Fatal(err)
	}
	observed := &acceptanceObservedWriter{Writer: w, entered: make(chan struct{})}
	c := newPacketLinkConn(nil, observed, packetAddress("192.0.2.1:53"))
	defer c.Close()
	payloads := [][]byte{bytes.Repeat([]byte{'a'}, 3000), []byte("second")}
	_ = c.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	done := make(chan error, 1)
	go func() { done <- c.WriteBatch(payloads) }()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("batch did not enter writer")
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("batch deadline ignored")
	}
	clear(payloads[0])
	clear(payloads[1])
	_ = c.SetWriteDeadline(time.Time{})
	mb, err := r.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err != nil {
		t.Fatal(err)
	}
	mb, err = r.ReadMultiBuffer()
	defer buf.ReleaseMulti(mb)
	if err != nil || len(mb) != 2 || !bytes.Equal(mb[0].Bytes(), bytes.Repeat([]byte{'a'}, 3000)) || string(mb[1].Bytes()) != "second" {
		t.Fatal("batch boundaries/ownership corrupted", err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteBatch([][]byte{[]byte("after FIN")}); err == nil {
		t.Fatal("batch accepted after half close")
	}
}

func TestPacketBatchCloseInterruptsBlockedWrite(t *testing.T) {
	r, w := pipe.New(pipe.WithSizeLimit(0))
	defer r.Interrupt()
	_ = w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("occupied"))})
	observed := &acceptanceObservedWriter{Writer: w, entered: make(chan struct{})}
	c := newPacketLinkConn(nil, observed, packetAddress("192.0.2.1:53"))
	done := make(chan error, 1)
	go func() { done <- c.WriteBatch([][]byte{[]byte("one"), []byte("two")}) }()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("writer not entered")
	}
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		r.Interrupt()
		t.Fatal("close blocked")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("batch remained blocked")
	}
	if err := c.WriteBatch([][]byte{[]byte("late")}); err == nil {
		t.Fatal("batch accepted after close")
	}
}

func TestPacketBatchRejectsOversizeBeforeWriting(t *testing.T) {
	w := &retainingPipeWriter{}
	c := newPacketLinkConn(nil, w, packetAddress("192.0.2.1:53"))
	defer c.Close()
	if err := c.WriteBatch([][]byte{make([]byte, 65536)}); err != io.ErrShortBuffer {
		t.Fatal(err)
	}
	if err := c.WriteBatch(make([][]byte, 65)); err != io.ErrShortBuffer {
		t.Fatal(err)
	}
	if w.calls != 0 {
		t.Fatal("invalid batch reached writer")
	}
}
