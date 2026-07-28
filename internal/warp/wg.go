// wg.go — WireGuard 兼容的 X25519 密钥对生成。
//
// WireGuard 用 Curve25519 ECDH(跟我们 securechan 同一个曲线),所以可以直接复用
// golang.org/x/crypto/curve25519。私钥来自 32 字节随机数,基点 9 乘出对应公钥。
//
// 注意:WireGuard 没有 RFC 7748 "clamping" 要求(虽然实现一般会做以兼容旧实现,
// curve25519.X25519 内部也会 clamp 一下,所以这里直接用随机字节即可)。

package warp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeypair 返回 base64(标准编码,带 padding,跟 wg/wg-quick 输出一致)的私钥和公钥。
// 返回值直接喂给 Cloudflare WARP 注册 API 和 Xray wireguard outbound 的 secretKey/publicKey 字段。
func GenerateKeypair() (privB64, pubB64 string, err error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return "", "", err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

// reservedFromClientID 把 Cloudflare 返回的 client_id(base64 编码,3 字节负载)解码成
// xray wireguard outbound 的 `reserved` 字段 — `[3]byte` 数组,作为 Cloudflare WARP 的
// client identifier。3x-ui WarpModal.tsx:61-67 同款实现。
func reservedFromClientID(clientIDB64 string) ([]byte, error) {
	if clientIDB64 == "" {
		return nil, errors.New("client_id is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(clientIDB64)
	if err != nil {
		// 兼容 unpadded variant
		raw, err = base64.RawStdEncoding.DecodeString(clientIDB64)
		if err != nil {
			return nil, err
		}
	}
	// Cloudflare 的 client_id 是 3 字节标识(用作 wireguard 数据包 reserved 字段)
	if len(raw) < 3 {
		return nil, errors.New("client_id decoded < 3 bytes")
	}
	out := make([]byte, 3)
	copy(out, raw[:3])
	return out, nil
}
