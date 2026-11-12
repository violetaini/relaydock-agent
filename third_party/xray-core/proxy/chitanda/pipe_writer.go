package chitanda

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

// A request owns pooled Xray buffers until WriteMultiBuffer takes ownership.
// Both the waiting caller and the worker hold a reference: a caller may return
// on deadline before the downstream write completes. Reuse only after both exit.
type pipeWriteRequest struct {
	mb     buf.MultiBuffer
	finish bool
	result chan error
	refs   atomic.Int32
}

var pipeWriteRequests = sync.Pool{New: func() any {
	return &pipeWriteRequest{result: make(chan error, 1)}
}}

func (r *pipeWriteRequest) release() {
	if r.refs.Add(-1) != 0 {
		return
	}
	r.mb = buf.ReleaseMulti(r.mb)
	r.finish = false
	select {
	case <-r.result: // An expired caller may not have consumed the completion.
	default:
	}
	pipeWriteRequests.Put(r)
}

// pipeWriteQueue keeps one downstream operation in flight. A recoverable
// deadline stops waiting, not the downstream transport. Input is copied only
// once, directly into Xray's pooled buffers, and completion objects are reused.
type pipeWriteQueue struct {
	writer    buf.Writer
	gate      chan struct{}
	jobs      chan *pipeWriteRequest
	done      chan struct{}
	exited    chan struct{}
	once      sync.Once
	closeOnce sync.Once

	mu      sync.Mutex
	closed  bool
	fin     bool
	err     error
	at      time.Time
	changed chan struct{}
}

func newPipeWriteQueue(writer buf.Writer) *pipeWriteQueue {
	w := &pipeWriteQueue{writer: writer, gate: make(chan struct{}, 1), jobs: make(chan *pipeWriteRequest, 1),
		done: make(chan struct{}), exited: make(chan struct{}), changed: make(chan struct{})}
	w.gate <- struct{}{}
	return w
}

func (w *pipeWriteQueue) start() {
	w.once.Do(func() { go w.run() })
}

func (w *pipeWriteQueue) complete(r *pipeWriteRequest, err error) {
	r.result <- err
	r.release()
	w.gate <- struct{}{}
}

func (w *pipeWriteQueue) run() {
	defer close(w.exited)
	for {
		select {
		case <-w.done:
			// Close and submission share mu, so no jobs can arrive after this.
			select {
			case r := <-w.jobs:
				w.complete(r, net.ErrClosed)
			default:
			}
			return
		case r := <-w.jobs:
			select {
			case <-w.done:
				w.complete(r, net.ErrClosed)
				return
			default:
			}
			finish := r.finish
			var err error
			if finish {
				err = common.Close(w.writer)
			} else {
				mb := r.mb
				r.mb = nil // Ownership passes to buf.Writer, including error paths.
				err = w.writer.WriteMultiBuffer(mb)
			}
			w.mu.Lock()
			w.err = err
			w.mu.Unlock()
			w.complete(r, err)
			if finish || err != nil {
				return
			}
		}
	}
}

func (w *pipeWriteQueue) watch() (time.Time, <-chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.at, w.changed
}

func pipeWriteTimer(at time.Time) (*time.Timer, <-chan time.Time) {
	if at.IsZero() {
		return nil, nil
	}
	t := time.NewTimer(time.Until(at))
	return t, t.C
}

func stopPipeWriteTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

func (w *pipeWriteQueue) acquire() error {
	w.start()
	for {
		at, changed := w.watch()
		if !at.IsZero() && !time.Now().Before(at) {
			return os.ErrDeadlineExceeded
		}
		timer, timeout := pipeWriteTimer(at)
		select {
		case <-w.gate:
			stopPipeWriteTimer(timer)
			return nil
		case <-w.done:
			stopPipeWriteTimer(timer)
			return net.ErrClosed
		case <-w.exited:
			stopPipeWriteTimer(timer)
			return w.terminalError()
		case <-changed:
			stopPipeWriteTimer(timer)
		case <-timeout:
		}
	}
}

func (w *pipeWriteQueue) terminalError() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	return io.ErrClosedPipe
}

func (w *pipeWriteQueue) await(result <-chan error) error {
	for {
		select {
		case err := <-result:
			return err
		default:
		}
		at, changed := w.watch()
		if !at.IsZero() && !time.Now().Before(at) {
			return os.ErrDeadlineExceeded
		}
		timer, timeout := pipeWriteTimer(at)
		select {
		case err := <-result:
			stopPipeWriteTimer(timer)
			return err
		case <-w.done:
			stopPipeWriteTimer(timer)
			return net.ErrClosed
		case <-w.exited:
			stopPipeWriteTimer(timer)
			select {
			case err := <-result:
				return err
			default:
			}
			return w.terminalError()
		case <-changed:
			stopPipeWriteTimer(timer)
		case <-timeout:
		}
	}
}

// submit transfers ownership to the worker only on success. The gate remains
// held until that worker finishes, even if the caller's deadline expires.
func (w *pipeWriteQueue) submit(r *pipeWriteRequest) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	if w.err != nil {
		return w.err
	}
	if w.fin || (!r.finish && w.writer == nil) {
		return io.ErrClosedPipe
	}
	if !w.at.IsZero() && !time.Now().Before(w.at) {
		return os.ErrDeadlineExceeded
	}
	w.fin = r.finish
	r.refs.Add(1)
	w.jobs <- r
	return nil
}

func (w *pipeWriteQueue) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := w.acquire(); err != nil {
		return 0, err
	}
	r := pipeWriteRequests.Get().(*pipeWriteRequest)
	r.refs.Store(1)
	r.mb = buf.MergeBytes(nil, p)
	defer r.release()
	if err := w.submit(r); err != nil {
		w.gate <- struct{}{}
		return 0, err
	}
	err := w.await(r.result)
	if err != nil && err != os.ErrDeadlineExceeded && err != net.ErrClosed {
		return 0, err
	}
	// Accepted bytes remain owned after timeout/close and must not be retried.
	return len(p), err
}

func (w *pipeWriteQueue) SetDeadline(at time.Time) error {
	w.mu.Lock()
	w.at = at
	close(w.changed)
	w.changed = make(chan struct{})
	w.mu.Unlock()
	return nil
}

// WriteDatagrams shares the stream queue's lifecycle and deadline gate, but
// preserves one Xray buffer per packet instead of splitting/merging UDP bytes.
// At most one bounded batch is owned, including when its caller times out.
func (w *pipeWriteQueue) WriteDatagrams(payloads [][]byte) (int, error) {
	if len(payloads) == 0 {
		return 0, nil
	}
	if len(payloads) > 64 {
		return 0, io.ErrShortBuffer
	}
	total := 0
	for _, p := range payloads {
		if len(p) > 65535 {
			return 0, io.ErrShortBuffer
		}
		total += len(p)
	}
	if err := w.acquire(); err != nil {
		return 0, err
	}
	r := pipeWriteRequests.Get().(*pipeWriteRequest)
	r.refs.Store(1)
	r.mb = make(buf.MultiBuffer, 0, len(payloads))
	for _, p := range payloads {
		r.mb = append(r.mb, ownedDatagram(p))
	}
	defer r.release()
	if err := w.submit(r); err != nil {
		w.gate <- struct{}{}
		return 0, err
	}
	err := w.await(r.result)
	if err != nil && err != os.ErrDeadlineExceeded && err != net.ErrClosed {
		return 0, err
	}
	return total, err
}

func (w *pipeWriteQueue) CloseWrite() error {
	w.mu.Lock()
	fin := w.fin
	w.mu.Unlock()
	if !fin {
		if err := w.acquire(); err != nil {
			// A concurrent half-close may already have completed.
			w.mu.Lock()
			finished := w.fin && !w.closed && w.err == nil
			w.mu.Unlock()
			if !finished {
				return err
			}
		} else {
			r := pipeWriteRequests.Get().(*pipeWriteRequest)
			r.refs.Store(1)
			r.finish = true
			defer r.release()
			if err := w.submit(r); err == nil {
				return w.await(r.result)
			} else {
				w.gate <- struct{}{}
				w.mu.Lock()
				finished := w.fin && !w.closed && w.err == nil
				w.mu.Unlock()
				if !finished {
					return err
				}
			}
		}
	}
	for {
		select {
		case <-w.exited:
			w.mu.Lock()
			err := w.err
			w.mu.Unlock()
			return err
		default:
		}
		at, changed := w.watch()
		if !at.IsZero() && !time.Now().Before(at) {
			return os.ErrDeadlineExceeded
		}
		timer, timeout := pipeWriteTimer(at)
		select {
		case <-w.exited:
			stopPipeWriteTimer(timer)
		case <-w.done:
			stopPipeWriteTimer(timer)
			return net.ErrClosed
		case <-changed:
			stopPipeWriteTimer(timer)
		case <-timeout:
		}
	}
}

func (w *pipeWriteQueue) Close() error {
	w.closeOnce.Do(func() {
		w.mu.Lock()
		w.closed = true
		close(w.done)
		w.mu.Unlock()
		// Abort does not acquire the gate held by an in-flight write/half-close.
		_ = common.Interrupt(w.writer)
		_ = common.Close(w.writer)
	})
	w.start()
	<-w.exited
	return nil
}
