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
	"github.com/xtls/xray-core/transport/pipe"
)

type acceptanceObservedWriter struct {
	*pipe.Writer
	entered chan struct{}
	once    sync.Once
}

func (w *acceptanceObservedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.once.Do(func() { close(w.entered) })
	return w.Writer.WriteMultiBuffer(mb)
}

func acceptanceBlockedPipe(t *testing.T) (*pipeConn, *pipe.Reader, *acceptanceObservedWriter) {
	t.Helper()
	r, w := pipe.New(pipe.WithSizeLimit(0))
	if err := w.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("occupied"))}); err != nil {
		t.Fatal(err)
	}
	observed := &acceptanceObservedWriter{Writer: w, entered: make(chan struct{})}
	c := newPipeConn(nil, observed)
	t.Cleanup(func() { r.Interrupt(); _ = c.Close() })
	return c, r, observed
}

func acceptanceStartWrite(t *testing.T, c *pipeConn, w *acceptanceObservedWriter) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := c.Write([]byte("blocked")); done <- err }()
	select {
	case <-w.entered:
	case <-time.After(time.Second):
		t.Fatal("write never entered downstream")
	}
	return done
}

func TestPipeWriterCloseUnblocksPendingWrite(t *testing.T) {
	c, r, w := acceptanceBlockedPipe(t)
	writeDone := acceptanceStartWrite(t, c, w)
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	select {
	case <-closeDone:
	case <-time.After(250 * time.Millisecond):
		t.Error("Close blocked behind a full downstream pipe; pending Write was not interrupted")
		r.Interrupt()
		<-closeDone
	}
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Error("Write still blocked after Close")
	}
}

func TestPipeWriterDeadlineAddedToPendingWrite(t *testing.T) {
	c, r, w := acceptanceBlockedPipe(t)
	done := acceptanceStartWrite(t, c, w)
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("write deadline error = %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Error("SetWriteDeadline did not wake an already pending Write")
		r.Interrupt()
		<-done
	}
}

func TestPipeWriterClearingDeadlineCancelsOldTimer(t *testing.T) {
	c, r, w := acceptanceBlockedPipe(t)
	_ = c.SetWriteDeadline(time.Now().Add(150 * time.Millisecond))
	done := acceptanceStartWrite(t, c, w)
	_ = c.SetWriteDeadline(time.Time{})
	select {
	case err := <-done:
		t.Errorf("cleared deadline still interrupted the write: %v", err)
		return
	case <-time.After(250 * time.Millisecond):
	}
	// Drain queued data so the pending write may complete normally.
	mb, err := r.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("cleared deadline write failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("write did not resume after downstream drain")
	}
}

func TestPipeWriterPresetWriteDeadlineError(t *testing.T) {
	c, r, w := acceptanceBlockedPipe(t)
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	done := acceptanceStartWrite(t, c, w)
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("timeout returned %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Error("preset deadline did not expire")
		r.Interrupt()
		<-done
	}
}

func TestPipeWriterPacketWriteHonorsExpiredDeadline(t *testing.T) {
	r, w := pipe.New()
	c := newPacketLinkConn(r, w, packetAddress("127.0.0.1:53"))
	t.Cleanup(func() { r.Interrupt(); _ = c.writes.Close(); _ = c.Close() })
	_ = c.SetWriteDeadline(time.Now().Add(-time.Second))
	n, err := c.Write([]byte("test"))
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("expired packet write returned (%d, %v), want (0, os.ErrDeadlineExceeded)", n, err)
	}
}

var _ io.Writer = (*pipeConn)(nil)

func TestPipeWriterTimeoutRecoveryRetainsOwnedBytes(t *testing.T) {
	c, r, w := acceptanceBlockedPipe(t)
	payload := []byte("owned-after-deadline")
	want := bytes.Clone(payload)
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() { n, err := c.Write(payload); done <- result{n, err} }()
	<-w.entered
	select {
	case got := <-done:
		if got.n != len(payload) || !errors.Is(got.err, os.ErrDeadlineExceeded) {
			t.Fatalf("accepted write = (%d, %v)", got.n, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("write did not time out")
	}
	clear(payload) // The caller owns its original slice again, including on timeout.
	_ = c.SetWriteDeadline(time.Time{})
	mb, err := r.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err != nil {
		t.Fatal(err)
	}
	mb, err = r.ReadMultiBuffer()
	got := make([]byte, mb.Len())
	mb.Copy(got)
	buf.ReleaseMulti(mb)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("accepted bytes corrupted or lost: %q, %v", got, err)
	}
	if n, err := c.Write([]byte("recovered")); n != 9 || err != nil {
		t.Fatalf("connection not reusable after deadline reset: %d, %v", n, err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	tail, err := io.ReadAll(&buf.BufferedReader{Reader: r})
	if string(tail) != "recovered" || err != nil {
		t.Fatalf("drain before EOF: %q, %v", tail, err)
	}
}

func TestPipeWriterDeadlineAlsoWakesWaitingWriters(t *testing.T) {
	c, _, w := acceptanceBlockedPipe(t)
	first := acceptanceStartWrite(t, c, w)
	type result struct {
		n   int
		err error
	}
	second := make(chan result, 1)
	go func() { n, err := c.Write([]byte("not-accepted")); second <- result{n, err} }()
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	select {
	case err := <-first:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight write not woken")
	}
	select {
	case got := <-second:
		if got.n != 0 || !errors.Is(got.err, os.ErrDeadlineExceeded) {
			t.Fatalf("waiting write = (%d, %v)", got.n, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting writer not woken")
	}
}

func TestPipeWriterExtendingDeadlineCancelsOldTimer(t *testing.T) {
	c, r, w := acceptanceBlockedPipe(t)
	_ = c.SetWriteDeadline(time.Now().Add(150 * time.Millisecond))
	done := acceptanceStartWrite(t, c, w)
	_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	select {
	case err := <-done:
		t.Fatalf("old deadline interrupted extended write: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	mb, err := r.ReadMultiBuffer()
	buf.ReleaseMulti(mb)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("extended write did not resume")
	}
}

func TestPipeWriterCloseAlsoUnblocksPendingHalfClose(t *testing.T) {
	c, _, w := acceptanceBlockedPipe(t)
	writeDone := acceptanceStartWrite(t, c, w)
	halfDone := make(chan error, 1)
	go func() { halfDone <- c.CloseWrite() }()
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	for name, done := range map[string]<-chan error{"write": writeDone, "half-close": halfDone, "close": closeDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("%s blocked during abort", name)
		}
	}
}

func TestPipeWriterConcurrentHalfCloseIsIdempotent(t *testing.T) {
	r, w := pipe.New()
	c := newPipeConn(nil, w)
	defer r.Interrupt()
	defer c.Close()
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() { done <- c.CloseWrite() }()
	}
	for i := 0; i < 16; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("concurrent CloseWrite: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent half-close blocked")
		}
	}
}

func TestPipeWriterPacketCloseStopsItsOwnWriter(t *testing.T) {
	w := &retainingPipeWriter{}
	defer func() { buf.ReleaseMulti(w.data) }()
	c := newPacketLinkConn(nil, w, packetAddress("127.0.0.1:53"))
	defer c.Close()
	if _, err := c.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Write([]byte("after-close")); n != 0 || err == nil {
		t.Fatalf("UDP writer still accepts data after Close: %d, %v", n, err)
	}
}

func TestPipeWriterPacketHalfCloseStopsItsOwnWriter(t *testing.T) {
	w := &retainingPipeWriter{}
	defer func() { buf.ReleaseMulti(w.data) }()
	c := newPacketLinkConn(nil, w, packetAddress("127.0.0.1:53"))
	defer c.Close()
	if _, err := c.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Write([]byte("after-close")); n != 0 || err == nil {
		t.Fatalf("UDP writer still accepts data after CloseWrite: %d, %v", n, err)
	}
}

type pipeDiscardWriter struct{}

func (pipeDiscardWriter) WriteMultiBuffer(mb buf.MultiBuffer) error { buf.ReleaseMulti(mb); return nil }

func BenchmarkPipeWriterPooledWrite(b *testing.B) {
	c := newPipeConn(nil, pipeDiscardWriter{})
	defer c.Close()
	p := make([]byte, 8192)
	b.SetBytes(int64(len(p)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if n, err := c.Write(p); n != len(p) || err != nil {
			b.Fatalf("Write: %d, %v", n, err)
		}
	}
}
