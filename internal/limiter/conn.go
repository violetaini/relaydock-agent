package limiter

import (
	"context"
	"net"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitedConn 把 net.Conn 包成"读/写都被 rate.Limiter 节流"的 conn。
//
// 用途:xtls-rprx-vision 协议在握手后会调 xray-core 的 UnwrapRawConn 拿底层 net.Conn,
// 然后 buf.NewReader/NewWriter(rawConn) 做 IO。把 rawConn 用本类型包一层后,vision 后续 Read/Write 全部走这里 → token bucket 生效。
//
// 关键设计:**不要 embed net.Conn**。如果 embed,Go 会自动 promote 底层 *net.TCPConn 的 SyscallConn()
// 方法,使 RateLimitedConn 满足 syscall.Conn 接口 → buf.NewReader/NewWriter 检测到这个接口后会拿 raw fd
// 直接 readv/writev syscall(common/buf/io.go:126,191),**绕过我们的 Read/Write,节流失效**。
// 所以这里用命名字段 `base` 并手动实现 net.Conn 完整接口,屏蔽 SyscallConn / WriteTo / ReadFrom 等所有
// xray-core fast-path 会嗅探的接口。
//
// xray-core 的 UnwrapRawConn 是基于已知类型断言展开 conn 链,不认识 *RateLimitedConn,所以 wrap 后该
// conn 永远不会被进一步 unwrap。两道防线叠加 → 100% 节流命中。
type RateLimitedConn struct {
	base    net.Conn
	limiter *rate.Limiter
}

func NewRateLimitedConn(c net.Conn, lim *rate.Limiter) *RateLimitedConn {
	return &RateLimitedConn{base: c, limiter: lim}
}

func (c *RateLimitedConn) Read(p []byte) (int, error) {
	n, err := c.base.Read(p)
	if n > 0 && c.limiter != nil {
		c.waitN(n)
	}
	return n, err
}

func (c *RateLimitedConn) Write(p []byte) (int, error) {
	if c.limiter == nil {
		return c.base.Write(p)
	}
	burst := c.limiter.Burst()
	written := 0
	for written < len(p) {
		chunk := len(p) - written
		if chunk > burst {
			chunk = burst
		}
		c.waitN(chunk)
		n, err := c.base.Write(p[written : written+chunk])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (c *RateLimitedConn) Close() error                       { return c.base.Close() }
func (c *RateLimitedConn) LocalAddr() net.Addr                { return c.base.LocalAddr() }
func (c *RateLimitedConn) RemoteAddr() net.Addr               { return c.base.RemoteAddr() }
func (c *RateLimitedConn) SetDeadline(t time.Time) error      { return c.base.SetDeadline(t) }
func (c *RateLimitedConn) SetReadDeadline(t time.Time) error  { return c.base.SetReadDeadline(t) }
func (c *RateLimitedConn) SetWriteDeadline(t time.Time) error { return c.base.SetWriteDeadline(t) }

// waitN 把一个写量 n 切成 burst 大小逐块 WaitN,避免请求超过 burst 时 WaitN 直接拒绝。
func (c *RateLimitedConn) waitN(n int) {
	burst := c.limiter.Burst()
	for n > 0 {
		take := n
		if take > burst {
			take = burst
		}
		_ = c.limiter.WaitN(context.Background(), take)
		n -= take
	}
}

// LookupBucketByEmail 在所有 inbound 上搜索 email 对应的 rate.Limiter (per-user bucket)。
// 用于 vision splice hook —— 那个上下文只拿得到 email,不知道 inbound tag。
func (l *Limiter) LookupBucketByEmail(email string) *rate.Limiter {
	if l == nil || email == "" {
		return nil
	}
	var found *rate.Limiter
	l.InboundInfo.Range(func(_, v any) bool {
		info := v.(*InboundInfo)
		var userLimit uint64
		info.UserInfo.Range(func(_, uv any) bool {
			u := uv.(UserInfo)
			if u.Email == email {
				userLimit = u.SpeedLimit
				return false
			}
			return true
		})
		if userLimit == 0 {
			return true
		}
		limit := determineRate(info.NodeSpeedLimit, userLimit)
		if limit == 0 {
			return true
		}
		if v, loaded := info.BucketHub.Load(email); loaded {
			found = v.(*rate.Limiter)
			return false
		}
		nb := rate.NewLimiter(rate.Limit(limit), calcBurst(limit))
		if v, loaded := info.BucketHub.LoadOrStore(email, nb); loaded {
			found = v.(*rate.Limiter)
		} else {
			found = nb
		}
		return false
	})
	return found
}
