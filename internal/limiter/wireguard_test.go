package limiter

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type wireGuardRateReaderStub struct {
	data        []byte
	closed      bool
	interrupted bool
	read        chan struct{}
	readOnce    sync.Once
	last        buf.MultiBuffer
	timeoutWait time.Duration
}

type wireGuardRateWriterStub struct {
	closed      bool
	interrupted bool
	writes      int
}

func (w *wireGuardRateWriterStub) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.writes++
	buf.ReleaseMulti(mb)
	return nil
}

func (w *wireGuardRateWriterStub) Close() error {
	w.closed = true
	return nil
}

func (w *wireGuardRateWriterStub) Interrupt() {
	w.interrupted = true
}

func (r *wireGuardRateReaderStub) next() buf.MultiBuffer {
	b := buf.New()
	_, _ = b.Write(r.data)
	r.last = buf.MultiBuffer{b}
	if r.read != nil {
		r.readOnce.Do(func() { close(r.read) })
	}
	return r.last
}

func (r *wireGuardRateReaderStub) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.next(), nil
}

func (r *wireGuardRateReaderStub) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	if r.timeoutWait > 0 {
		time.Sleep(r.timeoutWait)
	}
	return r.next(), nil
}

func (r *wireGuardRateReaderStub) Close() error {
	r.closed = true
	return nil
}

func (r *wireGuardRateReaderStub) Interrupt() {
	r.interrupted = true
}

func TestResolveWireGuardPeerUserUsesCanonicalHostIPAndReplacesMapping(t *testing.T) {
	l := New()
	const tag = "wg"

	l.AddInboundLimiter(tag, 0, []UserInfo{{UID: 1, Email: "alice@example.com"}}, WireGuardPeerUser{
		Address: "10.10.0.2/24",
		Email:   "alice@example.com",
	})

	if got, ok := l.ResolveWireGuardPeerUser(tag, "10.10.0.2"); !ok || got != "alice@example.com" {
		t.Fatalf("resolve peer user = %q, %v", got, ok)
	}

	l.SyncInboundLimiter(tag, 0, []UserInfo{{UID: 2, Email: "bob@example.com"}}, WireGuardPeerUser{
		Address: "fd00::2/128",
		Email:   "bob@example.com",
	})

	if _, ok := l.ResolveWireGuardPeerUser(tag, "10.10.0.2"); ok {
		t.Fatal("old wireguard peer mapping survived sync")
	}
	if got, ok := l.ResolveWireGuardPeerUser(tag, "fd00::2"); !ok || got != "bob@example.com" {
		t.Fatalf("resolved peer user after sync = %q, %v", got, ok)
	}
}

func TestSyncInboundLimiterCannotDisableWireGuardIdentityRequirement(t *testing.T) {
	l := New()
	const tag = "wg"
	l.AddInboundLimiter(tag, 0, nil, WireGuardPeerUser{
		Address: "10.10.0.2/32",
		Email:   "alice@example.com",
	})

	l.SyncInboundLimiter(tag, 0, nil)

	if !l.HasWireGuardPeerMappings(tag) {
		t.Fatal("empty snapshot disabled the WireGuard identity requirement")
	}
	if _, ok := l.ResolveWireGuardPeerUser(tag, "10.10.0.2"); ok {
		t.Fatal("stale WireGuard mapping survived an empty snapshot")
	}
}

func TestSyncInboundLimiterAppliesWireGuardTombstoneToExistingBucket(t *testing.T) {
	l := New()
	const (
		tag   = "wg"
		email = "alice@example.com"
	)
	peer := WireGuardPeerUser{Address: "10.10.0.2/32", Email: email}
	l.AddInboundLimiter(tag, 0, []UserInfo{{UID: 1, Email: email, SpeedLimit: 625000}}, peer)

	bucket, hasLimit, reject := l.GetUserBucket(tag, email, "10.10.0.2")
	if reject || !hasLimit || bucket == nil {
		t.Fatalf("GetUserBucket: reject=%v hasLimit=%v bucket=%v", reject, hasLimit, bucket)
	}

	l.SyncInboundLimiter(tag, 0, []UserInfo{{UID: 1, Email: email, SpeedLimit: 1, DeviceLimit: 1}}, peer)

	if got := bucket.Limit(); got != rate.Limit(1) {
		t.Fatalf("existing WireGuard bucket limit=%v, want 1 B/s", got)
	}
	if current, ok := l.InboundInfo.Load(tag); !ok {
		t.Fatal("WireGuard limiter disappeared after tombstone sync")
	} else if stored, ok := current.(*InboundInfo).BucketHub.Load(email); !ok || stored.(*rate.Limiter) != bucket {
		t.Fatal("tombstone sync replaced the bucket held by an existing connection")
	}
}

func TestRateReaderPreservesTimeoutReaderContract(t *testing.T) {
	source := &wireGuardRateReaderStub{data: []byte("wireguard")}
	reader := NewRateReader(source, rate.NewLimiter(rate.Inf, 1024))
	mb, err := reader.ReadMultiBufferTimeout(time.Second)
	if err != nil {
		t.Fatalf("ReadMultiBufferTimeout: %v", err)
	}
	defer buf.ReleaseMulti(mb)
	if got := mb.Len(); got != int32(len("wireguard")) {
		t.Fatalf("buffer length=%d", got)
	}
	if _, ok := reader.(common.Interruptible); !ok {
		t.Fatal("rate reader dropped the Interruptible contract")
	}
	if _, ok := reader.(common.Closable); !ok {
		t.Fatal("rate reader dropped the Closable contract")
	}
	if err := common.Interrupt(reader); err != nil {
		t.Fatalf("Interrupt: %v", err)
	}
	if !source.interrupted {
		t.Fatal("interrupt was not forwarded to the source reader")
	}
	if err := common.Close(reader); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !source.closed {
		t.Fatal("close was not forwarded to the source reader")
	}
}

func TestRateReaderCloseAndInterruptCancelLimiterWait(t *testing.T) {
	for _, test := range []struct {
		name   string
		cancel func(buf.TimeoutReader) error
	}{
		{name: "close", cancel: func(reader buf.TimeoutReader) error { return common.Close(reader) }},
		{name: "interrupt", cancel: func(reader buf.TimeoutReader) error { return common.Interrupt(reader) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &wireGuardRateReaderStub{data: []byte("xx"), read: make(chan struct{})}
			reader := NewRateReader(source, rate.NewLimiter(rate.Limit(1), 1))
			type readResult struct {
				mb  buf.MultiBuffer
				err error
			}
			result := make(chan readResult, 1)
			go func() {
				mb, err := reader.ReadMultiBuffer()
				result <- readResult{mb: mb, err: err}
			}()
			<-source.read

			if err := test.cancel(reader); err != nil {
				t.Fatalf("cancel reader: %v", err)
			}
			select {
			case got := <-result:
				if !errors.Is(got.err, context.Canceled) {
					t.Fatalf("read error=%v want context canceled", got.err)
				}
				if got.mb != nil {
					t.Fatalf("canceled read returned buffer: %#v", got.mb)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("limiter wait did not stop after cancellation")
			}
			if len(source.last) != 1 || source.last[0] != nil {
				t.Fatal("canceled limiter wait did not release the read buffer")
			}
		})
	}
}

func TestRateReaderTimeoutIncludesLimiterWaitAndReleasesBuffer(t *testing.T) {
	source := &wireGuardRateReaderStub{data: []byte("xx"), timeoutWait: 150 * time.Millisecond}
	reader := NewRateReader(source, rate.NewLimiter(rate.Limit(5), 1))
	started := time.Now()
	mb, err := reader.ReadMultiBufferTimeout(250 * time.Millisecond)
	if err != buf.ErrReadTimeout {
		t.Fatalf("ReadMultiBufferTimeout error=%v want %v", err, buf.ErrReadTimeout)
	}
	if mb != nil {
		t.Fatalf("timed out read returned buffer: %#v", mb)
	}
	if elapsed := time.Since(started); elapsed < 125*time.Millisecond || elapsed > 300*time.Millisecond {
		t.Fatalf("timeout did not cover the total read and limiter wait: %v", elapsed)
	}
	if len(source.last) != 1 || source.last[0] != nil {
		t.Fatal("timed out limiter wait did not release the read buffer")
	}
}

func TestRateWriterCloseAndInterruptCancelLimiterWait(t *testing.T) {
	for _, test := range []struct {
		name   string
		cancel func(buf.Writer) error
	}{
		{name: "close", cancel: func(writer buf.Writer) error { return common.Close(writer) }},
		{name: "interrupt", cancel: func(writer buf.Writer) error { return common.Interrupt(writer) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &wireGuardRateWriterStub{}
			limit := rate.NewLimiter(rate.Limit(1), 1)
			if !limit.Allow() {
				t.Fatal("failed to consume the initial limiter token")
			}
			writer := NewRateWriter(source, limit)
			buffer := buf.New()
			_, _ = buffer.Write([]byte("x"))
			mb := buf.MultiBuffer{buffer}
			result := make(chan error, 1)
			go func() { result <- writer.WriteMultiBuffer(mb) }()

			time.Sleep(20 * time.Millisecond)
			if err := test.cancel(writer); err != nil {
				t.Fatalf("cancel writer: %v", err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("write error=%v want context canceled", err)
				}
			case <-time.After(250 * time.Millisecond):
				t.Fatal("limiter wait did not stop after cancellation")
			}
			if len(mb) != 1 || mb[0] != nil {
				t.Fatal("canceled limiter wait did not release the write buffer")
			}
			if source.writes != 0 {
				t.Fatalf("underlying writer received %d writes after cancellation", source.writes)
			}
			if test.name == "close" && !source.closed {
				t.Fatal("close was not forwarded to the source writer")
			}
			if test.name == "interrupt" && !source.interrupted {
				t.Fatal("interrupt was not forwarded to the source writer")
			}
		})
	}
}
