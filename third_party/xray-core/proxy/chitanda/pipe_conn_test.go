package chitanda

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/server"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

// This writer intentionally implements only buf.Writer, like Xray's pipe.
// Keeping the buffers until after Write returns also checks their ownership.
type retainingPipeWriter struct {
	data  buf.MultiBuffer
	calls int
	err   error
}

func (w *retainingPipeWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.calls++
	if w.err != nil {
		buf.ReleaseMulti(mb)
		return w.err
	}
	w.data, _ = buf.MergeMulti(w.data, mb)
	return nil
}

func TestPipeConnWriteBufferBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, buf.Size - 1, buf.Size, buf.Size + 1, 16384, 32768, 128 * 1024, 2 * 1024 * 1024} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			w := &retainingPipeWriter{}
			defer func() { buf.ReleaseMulti(w.data) }()
			c := newPipeConn(nil, w)
			want := make([]byte, size)
			for i := range want {
				want[i] = byte(i * 31)
			}
			input := bytes.Clone(want)
			n, err := c.Write(input)
			if n != size || err != nil {
				t.Fatalf("Write(%d) = (%d, %v), want (%d, nil)", size, n, err, size)
			}
			clear(input) // caller may immediately reuse its input buffer
			got := make([]byte, w.data.Len())
			w.data.Copy(got)
			if !bytes.Equal(got, want) {
				t.Fatalf("payload lost, reordered, or retained by reference: got %d bytes, want %d", len(got), size)
			}
			if size == 0 && w.calls != 0 {
				t.Fatal("empty Write unexpectedly forwarded data")
			}
		})
	}
}

func TestPipeConnWritePropagatesDownstreamError(t *testing.T) {
	wantErr := errors.New("downstream write failed")
	for _, size := range []int{1, buf.Size, buf.Size + 1, 32768} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			w := &retainingPipeWriter{err: wantErr}
			c := newPipeConn(nil, w)
			_, err := c.Write(make([]byte, size))
			if !errors.Is(err, wantErr) {
				t.Fatalf("Write error = %v, want downstream error", err)
			}
		})
	}
}

func TestPipeConnRepeatedWritesAndHalfClose(t *testing.T) {
	r, w := pipe.New()
	defer r.Interrupt()
	c := newPipeConn(nil, w)
	defer c.Close()
	var want []byte
	for _, size := range []int{1380, 8192, 8193, 32768, 1, 16384} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		want = append(want, payload...)
		if n, err := c.Write(payload); n != size || err != nil {
			t.Fatalf("Write(%d) = (%d, %v)", size, n, err)
		}
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(&buf.BufferedReader{Reader: r})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("drain after half-close: got %d bytes, want %d, error %v", len(got), len(want), err)
	}
	if _, err := c.Write([]byte("after close")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after half-close = %v, want ErrClosedPipe", err)
	}
}

func TestPipeConnRawStreamLargeUpload(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	psk := []byte("local-only-regression-key-32-bytes")
	srv := server.NewStreamServer(psk, "test", nil, func(context.Context, string, string) (net.Conn, error) {
		// Loop back through a real Xray dispatcher pipe. This exercises the
		// adapter on both sides of the encrypted stream, without internet.
		r, w := pipe.New()
		return newPipeConn(r, w), nil
	})
	defer srv.Close()
	go func() { _ = srv.Serve(listener) }()
	cli, err := client.New(client.Config{
		Server: listener.Addr().String(), PSK: psk, ServerID: "test", TCPTransport: "stream",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := cli.DialContext(ctx, "tcp", "echo.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Cross the SDK's 1 MiB ramp-up threshold to exercise 32 KiB frames.
	want := bytes.Repeat([]byte("rawstream-regression-"), 128*1024)
	got := make([]byte, len(want))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(conn, got)
		readDone <- err
	}()
	if n, err := conn.Write(want); n != len(want) || err != nil {
		t.Fatalf("large stream write = (%d, %v), want %d bytes", n, err, len(want))
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("large upload payload corrupted")
	}
	// The same connection must still carry small streaming responses.
	if _, err := conn.Write([]byte("data: done\n\n")); err != nil {
		t.Fatal(err)
	}
	tail := make([]byte, len("data: done\n\n"))
	if _, err := io.ReadFull(conn, tail); err != nil || string(tail) != "data: done\n\n" {
		t.Fatalf("reused connection: %q, %v", tail, err)
	}
}
