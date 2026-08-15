package limiter

type UserInfo struct {
	UID         int
	Email       string
	SpeedLimit  uint64 // Bytes/s, 0 = unlimited
	DeviceLimit int    // 现语义 = 并发连接上限,0 = unlimited
	ConnGroup   string // 连接数计数分组键(同组共享配额);空 = 退化按 email 计数
}

// WireGuardPeerUser maps one WireGuard tunnel address to the RelayDock user
// email that owns it. Address is expected as a host CIDR (for example
// "10.66.0.2/32" or "fd00::2/128"); only the canonical host IP is used for
// runtime lookups because Xray exposes WireGuard traffic as Inbound.Source.
type WireGuardPeerUser struct {
	Address string
	Email   string
}
