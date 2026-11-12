package chitanda

import (
	"context"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	icmpmsg "github.com/violetaini/chitanda/pkg/icmp"
	"github.com/violetaini/chitanda/pkg/server"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

const maxUDPRoutes = 1024
const udpRouteIdle = time.Minute

type udpRouteKey struct {
	userIndex int
	session   uint64
	target    string
}
type udpRoute struct {
	conn    *packetLinkConn
	cancel  context.CancelFunc
	last    atomic.Int64
	once    sync.Once
	release func()
}
type icmpRoute struct {
	pconn   net.PacketConn
	target  net.IP
	tracker icmpmsg.EchoTracker
	cancel  context.CancelFunc
	last    atomic.Int64
	once    sync.Once
	release func()
}

func (e *udpRoute) close() {
	e.once.Do(func() {
		e.cancel()
		_ = e.conn.Close()
		if e.release != nil {
			e.release()
		}
	})
}
func (e *icmpRoute) close() {
	e.once.Do(func() {
		e.cancel()
		_ = e.pconn.Close()
		if e.release != nil {
			e.release()
		}
	})
}

type routeOpening struct {
	done    chan struct{}
	err     error
	release func()
}
type udpRoutes struct {
	ctx         context.Context
	cancel      context.CancelFunc
	dispatcher  routing.Dispatcher
	codecs      []*server.PlainUDPCodec
	outer       net.Conn
	mu          sync.Mutex
	writes      sync.Mutex
	closed      bool
	entries     map[udpRouteKey]*udpRoute
	icmpEntries map[udpRouteKey]*icmpRoute
	opening     map[udpRouteKey]*routeOpening
	dialICMP    func(ctx context.Context, address string) (net.PacketConn, error)
	wg          sync.WaitGroup
}

// A UDP association owns the route lifetime, while each authenticated packet
// supplies the user identity. Prefer packet-scoped values over the physical
// connection's inbound metadata so Xray does not lose the authenticated user.
type udpRouteValueContext struct {
	context.Context
	packet context.Context
}

func (c udpRouteValueContext) Value(key any) any {
	if value := c.packet.Value(key); value != nil {
		return value
	}
	return c.Context.Value(key)
}

func newUDPRoutes(ctx context.Context, d routing.Dispatcher, codecs []*server.PlainUDPCodec, outer net.Conn, dialICMP ...func(ctx context.Context, address string) (net.PacketConn, error)) *udpRoutes {
	ctx, cancel := context.WithCancel(ctx)
	var dialICMPFn func(ctx context.Context, address string) (net.PacketConn, error)
	if len(dialICMP) > 0 {
		dialICMPFn = dialICMP[0]
	}
	r := &udpRoutes{
		ctx:         ctx,
		cancel:      cancel,
		dispatcher:  d,
		codecs:      codecs,
		outer:       outer,
		entries:     make(map[udpRouteKey]*udpRoute),
		icmpEntries: make(map[udpRouteKey]*icmpRoute),
		opening:     make(map[udpRouteKey]*routeOpening),
		dialICMP:    dialICMPFn,
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				r.expire(now)
			}
		}
	}()
	return r
}

func (r *udpRoutes) expire(now time.Time) {
	r.mu.Lock()
	var expired []*udpRoute
	for key, entry := range r.entries {
		if now.Sub(time.Unix(0, entry.last.Load())) >= udpRouteIdle {
			delete(r.entries, key)
			expired = append(expired, entry)
		}
	}
	var expiredICMP []*icmpRoute
	for key, entry := range r.icmpEntries {
		if now.Sub(time.Unix(0, entry.last.Load())) >= udpRouteIdle {
			delete(r.icmpEntries, key)
			expiredICMP = append(expiredICMP, entry)
		}
	}
	r.mu.Unlock()
	for _, entry := range expired {
		entry.close()
	}
	for _, entry := range expiredICMP {
		entry.close()
	}
}

func (r *udpRoutes) evictOldestLocked() func() {
	if len(r.entries)+len(r.icmpEntries)+len(r.opening) < maxUDPRoutes {
		return nil
	}
	var oldestKey udpRouteKey
	var oldestEntry *udpRoute
	var oldestICMPKey udpRouteKey
	var oldestICMPEntry *icmpRoute
	var oldestTime int64 = math.MaxInt64

	for k, e := range r.entries {
		t := e.last.Load()
		if t < oldestTime {
			oldestTime = t
			oldestKey = k
			oldestEntry = e
		}
	}
	for k, e := range r.icmpEntries {
		t := e.last.Load()
		if t < oldestTime {
			oldestTime = t
			oldestICMPKey = k
			oldestICMPEntry = e
			oldestEntry = nil
		}
	}

	if oldestEntry != nil {
		delete(r.entries, oldestKey)
		return oldestEntry.close
	} else if oldestICMPEntry != nil {
		delete(r.icmpEntries, oldestICMPKey)
		return oldestICMPEntry.close
	}
	return nil
}

// beginRoute serializes only creation of the same target. No DNS, dispatch,
// socket Close, or blocking wait executes under the association table lock.
func (r *udpRoutes) beginRoute(ctx context.Context, key udpRouteKey) (*udpRoute, *icmpRoute, *routeOpening, error) {
	for {
		r.mu.Lock()
		if r.closed || r.ctx.Err() != nil {
			r.mu.Unlock()
			return nil, nil, nil, net.ErrClosed
		}
		if e := r.entries[key]; e != nil {
			r.mu.Unlock()
			return e, nil, nil, nil
		}
		if e := r.icmpEntries[key]; e != nil {
			r.mu.Unlock()
			return nil, e, nil, nil
		}
		if pending := r.opening[key]; pending != nil {
			r.mu.Unlock()
			select {
			case <-pending.done:
				if pending.err != nil {
					return nil, nil, nil, pending.err
				}
				continue
			case <-ctx.Done():
				return nil, nil, nil, ctx.Err()
			case <-r.ctx.Done():
				return nil, nil, nil, net.ErrClosed
			}
		}
		if len(r.opening) >= maxUDPRoutes {
			r.mu.Unlock()
			return nil, nil, nil, fmt.Errorf("UDP route creation limit reached")
		}
		evicted := r.evictOldestLocked()
		pending := &routeOpening{done: make(chan struct{})}
		r.opening[key] = pending
		r.wg.Add(1)
		r.mu.Unlock()
		if evicted != nil {
			evicted()
		}
		user := "invalid"
		if key.userIndex >= 0 && key.userIndex < len(r.codecs) && r.codecs[key.userIndex] != nil {
			user = r.codecs[key.userIndex].ResourceIdentity()
		}
		release, ok := reserveNativeRoute(user)
		if !ok {
			err := fmt.Errorf("native UDP route budget exhausted")
			r.finishRoute(key, pending, nil, nil, err)
			return nil, nil, nil, err
		}
		pending.release = release
		return nil, nil, pending, nil
	}
}

func (r *udpRoutes) finishRoute(key udpRouteKey, pending *routeOpening, udp *udpRoute, icmp *icmpRoute, err error) error {
	r.mu.Lock()
	if r.closed || r.ctx.Err() != nil {
		err = net.ErrClosed
	}
	if err == nil {
		if udp != nil {
			r.entries[key] = udp
			r.wg.Add(1)
			go r.receive(key, udp)
		}
		if icmp != nil {
			r.icmpEntries[key] = icmp
			r.wg.Add(1)
			go r.receiveICMP(key, icmp)
		}
	}
	pending.err = err
	delete(r.opening, key)
	close(pending.done)
	r.mu.Unlock()
	if err != nil {
		if udp != nil {
			udp.close()
		}
		if icmp != nil {
			icmp.close()
		}
		if pending.release != nil {
			pending.release()
		}
	}
	r.wg.Done()
	return err
}

func (r *udpRoutes) Write(ctx context.Context, userIndex int, sid uint64, dest xnet.Destination, payload []byte) error {
	key := udpRouteKey{userIndex, sid, dest.NetAddr()}
	entry, _, pending, err := r.beginRoute(ctx, key)
	if err != nil {
		return err
	}
	if pending != nil {
		flowCtx, cancel := context.WithCancel(udpRouteValueContext{Context: r.ctx, packet: ctx})
		link, dispatchErr := r.dispatcher.Dispatch(requestContext(flowCtx), dest)
		if dispatchErr != nil {
			cancel()
			return r.finishRoute(key, pending, nil, nil, dispatchErr)
		}
		entry = &udpRoute{conn: newPacketLinkConn(link.Reader, link.Writer, packetAddress(dest.NetAddr())), cancel: cancel, release: pending.release}
		entry.last.Store(time.Now().UnixNano())
		if err := r.finishRoute(key, pending, entry, nil, nil); err != nil {
			return err
		}
	}
	entry.last.Store(time.Now().UnixNano())
	_, err = entry.conn.Write(payload)
	if err != nil {
		r.remove(key, entry)
	}
	return err
}

func (r *udpRoutes) WriteICMP(ctx context.Context, userIndex int, sid uint64, targetAddr string, payload []byte) error {
	key := udpRouteKey{userIndex, sid, targetAddr}
	_, entry, pending, err := r.beginRoute(ctx, key)
	if err != nil {
		return err
	}
	if pending != nil {
		flowCtx, cancel := context.WithCancel(udpRouteValueContext{Context: r.ctx, packet: ctx})
		targetIP, resolveErr := icmpmsg.ResolveIP(flowCtx, strings.TrimPrefix(targetAddr, "icmp:"), false)
		if resolveErr != nil {
			cancel()
			return r.finishRoute(key, pending, nil, nil, resolveErr)
		}
		var pconn net.PacketConn
		if r.dialICMP != nil {
			pconn, err = r.dialICMP(flowCtx, targetIP.String())
		} else {
			network, addr := "ip4:icmp", "0.0.0.0"
			if targetIP.To4() == nil {
				network, addr = "ip6:ipv6-icmp", "::"
			}
			pconn, err = net.ListenPacket(network, addr)
		}
		if err != nil {
			cancel()
			return r.finishRoute(key, pending, nil, nil, err)
		}
		entry = &icmpRoute{pconn: pconn, target: targetIP, cancel: cancel, release: pending.release}
		entry.last.Store(time.Now().UnixNano())
		if err := r.finishRoute(key, pending, nil, entry, nil); err != nil {
			return err
		}
	}
	entry.last.Store(time.Now().UnixNano())
	wire, err := entry.tracker.PrepareRequest(payload, entry.target.To4() == nil)
	if err != nil {
		return err
	}
	_, err = entry.pconn.WriteTo(wire, &net.IPAddr{IP: entry.target})
	if err != nil {
		r.removeICMP(key, entry)
	}
	return err
}

func (r *udpRoutes) remove(key udpRouteKey, entry *udpRoute) {
	r.mu.Lock()
	if r.entries[key] == entry {
		delete(r.entries, key)
	}
	r.mu.Unlock()
	entry.close()
}

func (r *udpRoutes) removeICMP(key udpRouteKey, entry *icmpRoute) {
	r.mu.Lock()
	if r.icmpEntries[key] == entry {
		delete(r.icmpEntries, key)
	}
	r.mu.Unlock()
	entry.close()
}

func (r *udpRoutes) receive(key udpRouteKey, entry *udpRoute) {
	defer r.wg.Done()
	defer r.remove(key, entry)
	buffer := make([]byte, 65535)
	var codec *server.PlainUDPCodec
	if key.userIndex >= 0 && key.userIndex < len(r.codecs) {
		codec = r.codecs[key.userIndex]
	}
	if codec == nil {
		return
	}
	for {
		n, from, err := entry.conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		entry.last.Store(time.Now().UnixNano())
		encoded, err := codec.EncodeServerPacket(key.session, from.String(), buffer[:n], time.Now())
		if err != nil {
			continue
		}
		r.writes.Lock()
		_, err = r.outer.Write(encoded)
		r.writes.Unlock()
		if err != nil {
			return
		}
	}
}

func (r *udpRoutes) receiveICMP(key udpRouteKey, entry *icmpRoute) {
	defer r.wg.Done()
	defer r.removeICMP(key, entry)
	buffer := make([]byte, 2048)
	var codec *server.PlainUDPCodec
	if key.userIndex >= 0 && key.userIndex < len(r.codecs) {
		codec = r.codecs[key.userIndex]
	}
	if codec == nil {
		return
	}
	for {
		_ = entry.pconn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, from, err := entry.pconn.ReadFrom(buffer)
		if err != nil {
			return
		}
		fromAddr, ok := from.(*net.IPAddr)
		if !ok || !fromAddr.IP.Equal(entry.target) {
			continue
		}
		payload, ok := entry.tracker.RestoreReply(buffer[:n], entry.target.To4() == nil)
		if !ok {
			continue
		}
		entry.last.Store(time.Now().UnixNano())
		encoded, err := codec.EncodeServerPacket(key.session, "icmp:"+entry.target.String(), payload, time.Now())
		if err != nil {
			continue
		}
		r.writes.Lock()
		_, err = r.outer.Write(encoded)
		r.writes.Unlock()
		if err != nil {
			return
		}
	}
}

func (r *udpRoutes) Close() {
	r.cancel()
	r.mu.Lock()
	r.closed = true
	entries := r.entries
	r.entries = make(map[udpRouteKey]*udpRoute)
	icmpEntries := r.icmpEntries
	r.icmpEntries = make(map[udpRouteKey]*icmpRoute)
	r.mu.Unlock()
	// Process owns the outer association. Wake any response blocked on write
	// before joining readers; Close is also safe after EOF/caller cancellation.
	_ = r.outer.Close()
	for _, entry := range entries {
		entry.close()
	}
	for _, entry := range icmpEntries {
		entry.close()
	}
	r.wg.Wait()
}
