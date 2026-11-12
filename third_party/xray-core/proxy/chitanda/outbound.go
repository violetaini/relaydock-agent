package chitanda

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/violetaini/chitanda/pkg/client"
	icmpmsg "github.com/violetaini/chitanda/pkg/icmp"
	"github.com/violetaini/chitanda/pkg/plugin/autoscaler"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// OutboundHandler implements proxy.Outbound for Chitanda protocol in Xray
type OutboundHandler struct {
	config *OutboundConfig
	client *client.Client
	policy policy.Manager
	initMu sync.Mutex
	dialer internet.Dialer
}

type dialerKey struct{}

func withDialer(ctx context.Context, dialer internet.Dialer) context.Context {
	if dialer == nil {
		return ctx
	}
	return context.WithValue(ctx, dialerKey{}, dialer)
}

func getDialer(ctx context.Context) internet.Dialer {
	if d, ok := ctx.Value(dialerKey{}).(internet.Dialer); ok {
		return d
	}
	return nil
}

func NewOutboundHandler(ctx context.Context, config *OutboundConfig) (*OutboundHandler, error) {
	v := core.MustFromContext(ctx)
	pm := v.GetFeature(policy.ManagerType()).(policy.Manager)
	h := &OutboundHandler{config: config, policy: pm}
	dial := func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		d := getDialer(ctx)
		if d == nil {
			h.initMu.Lock()
			d = h.dialer
			h.initMu.Unlock()
		}
		if d == nil {
			return nil, fmt.Errorf("chitanda: Xray outbound dialer not ready: %w", client.ErrCarrierNotReady)
		}
		// Background carrier probes have no application outbound session. Xray's
		// sendThrough path requires one; never reuse a previous flow's Conn state.
		if len(session.OutboundsFromContext(ctx)) == 0 {
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
		}
		return d.Dial(ctx, dest)
	}

	transportMode := config.Transport
	if transportMode == "" {
		transportMode = client.TCPTransportH2
	}
	poolSize := config.PoolSize
	if poolSize <= 0 {
		poolSize = 4
	}

	var scaler client.AutoscalerPlugin
	if config.AutoScale || (config.MaxPoolSize > 0 && config.MaxPoolSize > poolSize) {
		maxCarriers := int(config.MaxPoolSize)
		if maxCarriers <= 0 {
			maxCarriers = 8
		}
		scalerCfg := autoscaler.Config{
			MaxCarriers: maxCarriers,
		}
		if config.ScaleUpThreshold > 0 {
			scalerCfg.ScaleUpThreshold = int64(config.ScaleUpThreshold)
		}
		if config.ScaleDownIdle > 0 {
			scalerCfg.ScaleDownIdle = time.Duration(config.ScaleDownIdle) * time.Second
		}
		if config.Cooldown > 0 {
			scalerCfg.Cooldown = time.Duration(config.Cooldown) * time.Millisecond
		}
		scaler = autoscaler.New(scalerCfg)
	}

	cli, err := client.New(client.Config{
		Server:             config.Server,
		ServerName:         config.ServerName,
		ServerID:           config.ServerId,
		PSK:                []byte(config.Psk),
		Path:               config.Path,
		TCPTransport:       transportMode,
		TCPPoolSize:        int(poolSize),
		UDPPoolSize:        int(poolSize),
		MaxPoolSize:        int(config.MaxPoolSize),
		Autoscaler:         scaler,
		InsecureSkipVerify: config.AllowInsecure,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := xnet.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			return dial(ctx, dest)
		},
		ResolveUDP: func(ctx context.Context, network, addr string) (*net.UDPAddr, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			host, portText, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid UDP server port")
			}
			if ip := net.ParseIP(host); ip != nil {
				return &net.UDPAddr{IP: ip, Port: port}, nil
			}
			resolver, ok := v.GetFeature(dns.ClientType()).(dns.Client)
			if !ok {
				return nil, fmt.Errorf("chitanda: Xray DNS client unavailable")
			}
			ips, _, err := resolver.LookupIP(host, dns.IPOption{IPv4Enable: true, IPv6Enable: true})
			if err != nil {
				return nil, err
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("chitanda: no IP for UDP server")
			}
			return &net.UDPAddr{IP: ips[0], Port: port}, nil
		},
		DialPacket: func(ctx context.Context, remote *net.UDPAddr) (net.PacketConn, error) {
			dest, err := xnet.ParseDestination("udp:" + remote.String())
			if err != nil {
				return nil, err
			}
			conn, err := dial(ctx, dest)
			if err != nil {
				return nil, err
			}
			packets := newPacketLinkConn(newFullPacketReader(conn), buf.NewWriter(conn), remote)
			return &connectedPacketConn{Conn: conn, packets: packets, remote: remote}, nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("init chitanda client: %w", err)
	}

	h.client = cli
	return h, nil
}

func (h *OutboundHandler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	if dialer != nil {
		h.initMu.Lock()
		h.dialer = dialer
		h.initMu.Unlock()
	}
	ctx = withDialer(ctx, dialer)
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 || !outbounds[len(outbounds)-1].Target.IsValid() {
		return fmt.Errorf("chitanda: target not found in context")
	}

	destination := outbounds[len(outbounds)-1].Target
	targetAddr := destination.NetAddr()

	if destination.Network == xnet.Network_TCP {
		conn, err := h.client.DialContext(ctx, "tcp", targetAddr)
		if err != nil {
			return fmt.Errorf("chitanda dial tcp: %w", err)
		}
		defer conn.Close()
		abort := func() {
			_ = conn.Close()
			_ = common.Interrupt(link.Reader)
			_ = common.Interrupt(link.Writer)
		}
		stop := context.AfterFunc(ctx, abort)
		defer stop()
		defer abort()
		activity := make(activitySignal, 1)

		uploadDone := make(chan error, 1)
		go func() {
			var writer buf.Writer
			if bw, ok := conn.(batchWriter); ok {
				writer = &streamBufWriter{bw: bw}
			} else {
				writer = buf.NewWriter(conn)
			}
			err := buf.Copy(link.Reader, writer, buf.UpdateActivity(activity))
			if err == nil {
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					err = cw.CloseWrite()
				}
			}
			uploadDone <- err
		}()
		downloadDone := make(chan error, 1)
		go func() {
			err := buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(activity))
			if err == nil {
				_ = common.Close(link.Writer)
			}
			downloadDone <- err
		}()
		idle := 300 * time.Second
		if h.policy != nil && h.policy.ForLevel(0).Timeouts.ConnectionIdle > 0 {
			idle = h.policy.ForLevel(0).Timeouts.ConnectionIdle
		}
		timer := time.NewTimer(idle)
		defer timer.Stop()
		var result error
		for uploadDone != nil || downloadDone != nil {
			select {
			case <-ctx.Done():
				result = ctx.Err()
			case <-timer.C:
				result = fmt.Errorf("chitanda: idle timeout")
			case <-activity:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(idle)
			case err := <-uploadDone:
				uploadDone = nil
				result = err
			case err := <-downloadDone:
				downloadDone = nil
				result = err
			}
			if result != nil {
				abort()
				if uploadDone != nil {
					<-uploadDone
				}
				if downloadDone != nil {
					<-downloadDone
				}
				return result
			}
		}
		return nil
	} else if destination.Network == xnet.Network_UDP {
		return h.processUDP(ctx, link, packetAddress(targetAddr))
	}

	return fmt.Errorf("unsupported network: %v", destination.Network)
}

type activitySignal chan struct{}

func (s activitySignal) Update() {
	select {
	case s <- struct{}{}:
	default:
	}
}

func (h *OutboundHandler) processUDP(ctx context.Context, link *transport.Link, target net.Addr) error {
	pconn, err := h.client.ListenPacket(ctx)
	if err != nil {
		return fmt.Errorf("chitanda listen udp: %w", err)
	}
	abort := func() {
		_ = pconn.Close()
		_ = common.Interrupt(link.Reader)
		_ = common.Interrupt(link.Writer)
	}
	stop := context.AfterFunc(ctx, abort)
	defer stop()
	defer abort()
	uploadDone := make(chan error, 1)
	go func() {
		defer pconn.Close() // An ended uplink must wake the blocked downlink.
		batchConn, hasBatch := pconn.(interface {
			WriteBatch([][]byte, []net.Addr) error
		})
		for {
			mb, readErr := link.Reader.ReadMultiBuffer()
			var writeErr error
			if hasBatch && len(mb) > 1 {
				payloads := make([][]byte, 0, len(mb))
				addrs := make([]net.Addr, 0, len(mb))
				for _, b := range mb {
					if !b.IsEmpty() {
						addr := target
						if b.UDP != nil && b.UDP.IsValid() {
							addr = packetAddress(b.UDP.NetAddr())
						}
						addr, writeErr = icmpAddressForPacket(addr, b.Bytes())
						if writeErr != nil {
							break
						}
						payloads = append(payloads, b.Bytes())
						addrs = append(addrs, addr)
					}
				}
				if len(payloads) > 0 && writeErr == nil {
					writeErr = batchConn.WriteBatch(payloads, addrs)
				}
			} else {
				for _, b := range mb {
					addr := target
					if b.UDP != nil && b.UDP.IsValid() {
						addr = packetAddress(b.UDP.NetAddr())
					}
					addr, writeErr = icmpAddressForPacket(addr, b.Bytes())
					if writeErr != nil {
						break
					}
					if _, writeErr = pconn.WriteTo(b.Bytes(), addr); writeErr != nil {
						break
					}
				}
			}
			buf.ReleaseMulti(mb)
			if writeErr != nil {
				uploadDone <- writeErr
				return
			}
			if readErr != nil {
				uploadDone <- readErr
				return
			}
		}
	}()

	recvBuf := make([]byte, 65535)
	var downloadErr error
	var (
		lastIP   net.IP
		lastPort int
		lastDest xnet.Destination
		hasDest  bool
	)
	for {
		n, from, readErr := pconn.ReadFrom(recvBuf)
		if readErr != nil {
			downloadErr = readErr
			break
		}
		b := ownedDatagram(recvBuf[:n])
		if from != nil {
			if udpAddr, ok := from.(*net.UDPAddr); ok {
				if !hasDest || lastPort != udpAddr.Port || !udpAddr.IP.Equal(lastIP) {
					lastIP = append(lastIP[:0], udpAddr.IP...)
					lastPort = udpAddr.Port
					lastDest = xnet.UDPDestination(xnet.IPAddress(udpAddr.IP), xnet.Port(udpAddr.Port))
					hasDest = true
				}
				dest := lastDest
				b.UDP = &dest
			} else if icmpAddr, ok := from.(*client.ICMPAddr); ok && icmpAddr.IP != nil {
				dest := xnet.UDPDestination(xnet.IPAddress(icmpAddr.IP), xnet.Port(0))
				b.UDP = &dest
			} else if dest, err := xnet.ParseDestination("udp:" + from.String()); err == nil {
				b.UDP = &dest
			}
		}
		if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			downloadErr = err
			break
		}
	}
	abort()
	uploadErr := <-uploadDone
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if uploadErr != nil && uploadErr != io.EOF && uploadErr != net.ErrClosed {
		return uploadErr
	}
	if uploadErr == io.EOF || downloadErr == io.EOF || downloadErr == net.ErrClosed {
		return nil
	}
	return downloadErr
}

// Xray has no ICMP network enum; an explicitly addressed UDP port zero carrying
// a valid Echo Request is the Chitanda ICMP convention.
func icmpAddressForPacket(addr net.Addr, payload []byte) (net.Addr, error) {
	if addr == nil {
		return nil, errors.New("missing datagram destination")
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil || port != "0" {
		return addr, nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("ICMP destination must be an IP address: %q", host)
	}
	if err := icmpmsg.ValidateEchoRequest(payload, ip.To4() == nil); err != nil {
		return nil, err
	}
	return &client.ICMPAddr{IP: ip}, nil
}

func (h *OutboundHandler) Close() error {
	if h.client != nil {
		h.client.Close()
	}
	return nil
}

type batchWriter interface {
	WriteBatch(buffers [][]byte) (int, error)
}

type streamBufWriter struct {
	bw batchWriter
}

func (w *streamBufWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if mb.IsEmpty() {
		return nil
	}
	var stackBufs [32][]byte
	var bufs [][]byte
	if len(mb) <= len(stackBufs) {
		bufs = stackBufs[:0]
	} else {
		bufs = make([][]byte, 0, len(mb))
	}
	for _, b := range mb {
		if !b.IsEmpty() {
			bufs = append(bufs, b.Bytes())
		}
	}
	if len(bufs) == 0 {
		return nil
	}
	_, err := w.bw.WriteBatch(bufs)
	return err
}

func init() {
	common.Must(common.RegisterConfig((*OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewOutboundHandler(ctx, config.(*OutboundConfig))
	}))
}
