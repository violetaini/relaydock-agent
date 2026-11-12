package udp

import (
	"context"
 "sync/atomic"
 "math/bits"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/transport/internet"
)

type HubOption func(h *Hub)

func HubCapacity(capacity int) HubOption {
	return func(h *Hub) {
		h.capacity = capacity
	}
}

func HubReceiveOriginalDestination(r bool) HubOption {
	return func(h *Hub) {
		h.recvOrigDest = r
	}
}

func HubPacketSize(size int32) HubOption {
	return func(h *Hub) { if size > buf.Size && size <= 65535 { h.packetSize = size } }
}

func HubQueueBudget() HubOption { return func(h *Hub) { h.budgeted = true } }

type Hub struct {
 budgeted bool
 queueBytes int64
 queueDrops uint64
	packetSize int32
	conn         net.PacketConn
	udpConn      *net.UDPConn
	cache        chan *udp.Packet
	capacity     int
	recvOrigDest bool
}

func ListenUDP(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, options ...HubOption) (*Hub, error) {
	hub := &Hub{
		capacity:     256,
		recvOrigDest: false,
	}
	for _, opt := range options {
		opt(hub)
	}

	if address.Family().IsDomain() && address.Domain() == "localhost" {
		address = net.LocalHostIP
	}

	if address.Family().IsDomain() {
		return nil, errors.New("domain address is not allowed for listening: ", address.Domain())
	}

	var sockopt *internet.SocketConfig
	if streamSettings != nil {
		sockopt = streamSettings.SocketSettings
	}
	if sockopt != nil && sockopt.ReceiveOriginalDestAddress {
		hub.recvOrigDest = true
	}

	var err error
	hub.conn, err = internet.ListenSystemPacket(ctx, &net.UDPAddr{
		IP:   address.IP(),
		Port: int(port),
	}, sockopt)
	if err != nil {
		return nil, err
	}

	raw := hub.conn

	if streamSettings.UdpmaskManager != nil {
		hub.conn, err = streamSettings.UdpmaskManager.WrapPacketConnServer(raw)
		if err != nil {
			raw.Close()
			return nil, errors.New("mask err").Base(err)
		}
	}

	errors.LogInfo(ctx, "listening UDP on ", address, ":", port)
	hub.udpConn, _ = hub.conn.(*net.UDPConn)
	hub.cache = make(chan *udp.Packet, hub.capacity)

	go hub.start()
	return hub, nil
}

// Close implements net.Listener.
func (h *Hub) Close() error {
	h.conn.Close()
	return nil
}

func (h *Hub) WriteTo(payload []byte, dest net.Destination) (int, error) {
	return h.conn.WriteTo(payload, &net.UDPAddr{
		IP:   dest.Address.IP(),
		Port: int(dest.Port),
	})
}

func (h *Hub) start() {
	c := h.cache
	defer close(c)

	oobBytes := make([]byte, 256)
	var largePacket []byte
	if h.packetSize > buf.Size { largePacket = make([]byte, h.packetSize) }

	for {
		buffer := buf.New()
		var noob int
		var udpAddr *net.UDPAddr
		rawBytes := buffer.Extend(buf.Size)
		if largePacket != nil { rawBytes = largePacket }

		var n int
		var err error
		if h.udpConn != nil {
			n, noob, _, udpAddr, err = ReadUDPMsg(h.udpConn, rawBytes, oobBytes)
		} else {
			var addr net.Addr
			n, addr, err = h.conn.ReadFrom(rawBytes)
			if err == nil {
				udpAddr = addr.(*net.UDPAddr)
			}
		}

		if err != nil {
			errors.LogInfoInner(context.Background(), err, "failed to read UDP msg")
			buffer.Release()
			break
		}
		if !h.reserveQueueBytes(int64(max(int(buf.Size), 1<<bits.Len(uint(max(1, n)-1))))+128) { buffer.Release(); atomic.AddUint64(&h.queueDrops, 1); continue }
		if largePacket != nil {
			buffer.Release()
			buffer = buf.NewWithSize(int32(max(1, n)))
			copy(buffer.Extend(int32(n)), rawBytes[:n])
		}
		buffer.Resize(0, int32(n))

		if buffer.IsEmpty() {
			h.ReleaseQueuedPacket(&udp.Packet{Payload: buffer})
			buffer.Release()
			continue
		}

		payload := &udp.Packet{
			Payload: buffer,
			Source:  net.UDPDestination(net.IPAddress(udpAddr.IP), net.Port(udpAddr.Port)),
		}
		if h.recvOrigDest && noob > 0 {
			payload.Target = RetrieveOriginalDest(oobBytes[:noob])
			if payload.Target.IsValid() {
				errors.LogDebug(context.Background(), "UDP original destination: ", payload.Target)
			} else {
				errors.LogInfo(context.Background(), "failed to read UDP original destination")
			}
		}

		select {
		case c <- payload:
		default:
			h.ReleaseQueuedPacket(payload)
			atomic.AddUint64(&h.queueDrops, 1)
			buffer.Release()
			payload.Payload = nil
		}
	}
}

// Addr implements net.Listener.
func (h *Hub) Addr() net.Addr {
	return h.conn.LocalAddr()
}

var globalUDPQueueBytes int64

func (h *Hub) reserveQueueBytes(size int64) bool {
    if !h.budgeted { return true }
    for {
        used := atomic.LoadInt64(&h.queueBytes)
        if size > (16<<20)-used { return false }
        if atomic.CompareAndSwapInt64(&h.queueBytes, used, used+size) { break }
    }
    for {
        used := atomic.LoadInt64(&globalUDPQueueBytes)
        if size > (64<<20)-used { atomic.AddInt64(&h.queueBytes,-size); return false }
        if atomic.CompareAndSwapInt64(&globalUDPQueueBytes, used, used+size) { return true }
    }
}

func (h *Hub) ReleaseQueuedPacket(p *udp.Packet) {
    if !h.budgeted { return }
    // Standard buffers retain buf.Size; large native records use the next
    // bytespool size class. Reserve and release exactly the same amount.
    size := int64(max(int(buf.Size), 1<<bits.Len(uint(max(1,int(p.Payload.Len()))-1))))+128
    atomic.AddInt64(&h.queueBytes,-size)
    atomic.AddInt64(&globalUDPQueueBytes,-size)
}

func (h *Hub) QueueStats() (int64,uint64) { return atomic.LoadInt64(&h.queueBytes),atomic.LoadUint64(&h.queueDrops) }

func (h *Hub) Receive() <-chan *udp.Packet {
	return h.cache
}
