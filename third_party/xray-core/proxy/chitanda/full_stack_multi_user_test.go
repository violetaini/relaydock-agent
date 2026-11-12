package chitanda_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	_ "github.com/xtls/xray-core/main/distro/all"
	_ "github.com/xtls/xray-core/main/json"
)

// Exercise real Xray JSON loading, inbound routing, policy and stats rather
// than only inspecting a mock dispatcher's context.
func TestChitandaFullStackMultiUserAccounting(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenPort := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	keyAlice := "alice-key-at-least-32-bytes-long!"
	keyBob := "bob---key-at-least-32-bytes-long!"
	config := fmt.Sprintf(`{
		"log":{"loglevel":"warning"},
		"stats":{},
		"policy":{"levels":{"0":{"statsUserUplink":true,"statsUserDownlink":true}}},
		"inbounds":[{"tag":"chitanda-test","listen":"127.0.0.1","port":%d,"protocol":"chitanda",
			"settings":{"transport":"stream","users":[{"email":"alice","psk":%q},{"email":"bob","psk":%q}]}}],
		"outbounds":[{"tag":"direct","protocol":"freedom"}]
	}`, listenPort, keyAlice, keyBob)
	instance, err := core.StartInstance("json", []byte(config))
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		var data [2048]byte
		for {
			n, peer, err := udpEcho.ReadFromUDP(data[:])
			if err != nil {
				return
			}
			_, _ = udpEcho.WriteToUDP(data[:n], peer)
		}
	}()

	for _, user := range []struct{ email, key, payload string }{
		{"alice", keyAlice, "alice traffic"},
		{"bob", keyBob, "bob traffic is different"},
	} {
		c, err := client.New(client.Config{Server: fmt.Sprintf("127.0.0.1:%d", listenPort), PSK: []byte(user.key), TCPTransport: "stream"})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := c.DialContext(ctx, "tcp", echo.Addr().String())
		if err != nil {
			cancel()
			c.Close()
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte(user.payload)); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, len(user.payload))
		if _, err := io.ReadFull(conn, response); err != nil || string(response) != user.payload {
			t.Fatalf("%s echo=%q err=%v", user.email, response, err)
		}
		_ = conn.Close()
		cancel()
		c.Close()
	}
	for _, user := range []struct{ email, key, payload string }{
		{"alice", keyAlice, "alice udp"},
		{"bob", keyBob, "bob udp payload"},
	} {
		c, err := client.New(client.Config{Server: fmt.Sprintf("127.0.0.1:%d", listenPort), PSK: []byte(user.key), TCPTransport: "stream"})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		packet, err := c.ListenPacket(ctx)
		if err != nil {
			cancel()
			c.Close()
			t.Fatal(err)
		}
		_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := packet.WriteTo([]byte(user.payload), udpEcho.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 2048)
		n, _, err := packet.ReadFrom(response)
		if err != nil || string(response[:n]) != user.payload {
			t.Fatalf("%s UDP echo=%q err=%v", user.email, response[:n], err)
		}
		_ = packet.Close()
		cancel()
		c.Close()
	}

	manager, ok := instance.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		t.Fatal("Xray stats manager unavailable")
	}
	for _, user := range []struct {
		email, tcpPayload, udpPayload string
	}{
		{"alice", "alice traffic", "alice udp"},
		{"bob", "bob traffic is different", "bob udp payload"},
	} {
		for _, direction := range []string{"uplink", "downlink"} {
			name := "user>>>" + user.email + ">>>traffic>>>" + direction
			counter := manager.GetCounter(name)
			want := int64(len(user.tcpPayload) + len(user.udpPayload))
			if counter == nil || counter.Value() != want {
				t.Fatalf("%s = %v, want %d", name, counter, want)
			}
		}
	}
}
