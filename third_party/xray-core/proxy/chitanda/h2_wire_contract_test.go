package chitanda_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Injected into both downstream modules with only its package name changed.
// Test actual HTTP/2 frames rather than patched source markers.
func TestChitandaH2WireContract(t *testing.T) {
	fixture := httptest.NewTLSServer(nil)
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type observation struct {
		window uint32
		padded bool
		err    error
	}
	result := make(chan observation, 1)
	go func() {
		o := observation{}
		defer func() { result <- o }()
		raw, err := ln.Accept()
		if err != nil {
			o.err = err
			return
		}
		defer raw.Close()
		tc := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		if o.err = tc.Handshake(); o.err != nil {
			return
		}
		preface := make([]byte, len(http2.ClientPreface))
		if _, o.err = io.ReadFull(tc, preface); o.err != nil {
			return
		}
		if string(preface) != http2.ClientPreface {
			o.err = fmt.Errorf("invalid preface")
			return
		}
		fr := http2.NewFramer(tc, tc)
		if o.err = fr.WriteSettings(); o.err != nil {
			return
		}
		for {
			f, e := fr.ReadFrame()
			if e != nil {
				o.err = e
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = f.ForeachSetting(func(s http2.Setting) error {
						if s.ID == http2.SettingInitialWindowSize {
							o.window = s.Val
						}
						return nil
					})
					if o.err = fr.WriteSettingsAck(); o.err != nil {
						return
					}
				}
			case *http2.HeadersFrame:
				var block bytes.Buffer
				e := hpack.NewEncoder(&block)
				for _, field := range []hpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "x-session-ok", Value: "1"}, {Name: "x-session-framing", Value: "1"}} {
					if o.err = e.WriteField(field); o.err != nil {
						return
					}
				}
				if o.err = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: f.StreamID, EndHeaders: true, BlockFragment: block.Bytes()}); o.err != nil {
					return
				}
			case *http2.DataFrame:
				if len(f.Data()) > 0 {
					o.padded = f.Header().Flags.Has(http2.FlagDataPadded)
					return
				}
			}
		}
	}()
	c, err := client.New(client.Config{Server: ln.Addr().String(), ServerName: "localhost", Path: "/wire", PSK: bytes.Repeat([]byte{'x'}, 32), TCPTransport: "h2", TCPPoolSize: 1, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(ctx, "tcp", "192.0.2.1:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write(bytes.Repeat([]byte{'d'}, 512)); err != nil {
		t.Fatal(err)
	}
	select {
	case o := <-result:
		if o.err != nil {
			t.Fatal(o.err)
		}
		if o.window != 64<<20 {
			t.Fatalf("actual H2 window=%d, want 64MiB", o.window)
		}
		if os.Getenv("CHITANDA_REQUIRE_H2_PADDING") == "1" && !o.padded {
			t.Fatal("release contract: H2 DATA padding not active")
		}
		t.Logf("actual window=%d padded=%v", o.window, o.padded)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
