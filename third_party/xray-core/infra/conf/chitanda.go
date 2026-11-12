package conf

import (
	"fmt"
	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/server"
	"github.com/xtls/xray-core/proxy/chitanda"
	"google.golang.org/protobuf/proto"
	"net"
	"strings"
)

type ChitandaUser struct {
	Email string `json:"email"`
	PSK   string `json:"psk"`
	Level uint32 `json:"level"`
}

type ChitandaInboundConfig struct {
	PSK           string          `json:"psk"`
	Path          string          `json:"path"`
	Transport     string          `json:"transport"`
	StrictSNI     string          `json:"strict_sni"`
	Fallback      string          `json:"fallback"`
	ServerID      string          `json:"server_id"`
	ServerId      string          `json:"serverId"`
	ServerHyphen  string          `json:"server-id"`
	ReplayFile    string          `json:"replay_file"`
	CertFile      string          `json:"cert_file"`
	CertFileCamel string          `json:"certFile"`
	KeyFile       string          `json:"key_file"`
	KeyFileCamel  string          `json:"keyFile"`
	Users         []*ChitandaUser `json:"users"`
}

// InheritTLS reuses an explicitly configured Xray server certificate for the
// native QUIC listener. Never manufacture a protocol-identifying certificate.
func (c *ChitandaInboundConfig) InheritTLS(stream *StreamConfig) {
	if c.CertFile != "" || c.CertFileCamel != "" || c.KeyFile != "" || c.KeyFileCamel != "" {
		return
	}
	if stream == nil || stream.TLSSettings == nil {
		return
	}
	for _, cert := range stream.TLSSettings.Certs {
		if cert != nil && (cert.Usage == "" || strings.EqualFold(cert.Usage, "encipherment")) && cert.CertFile != "" && cert.KeyFile != "" {
			c.CertFile, c.KeyFile = cert.CertFile, cert.KeyFile
			return
		}
	}
}

func validateChitanda(psk, mode string) error {
	if len(psk) < 32 {
		return fmt.Errorf("chitanda: psk must contain at least 32 bytes")
	}
	switch mode {
	case "", "stream", "h1", "plain-h1", "h2", "h3", "auto":
		return nil
	default:
		return fmt.Errorf("chitanda: unsupported transport %q", mode)
	}
}

func (c *ChitandaInboundConfig) Build() (proto.Message, error) {
	switch c.Transport {
	case "", "stream", "h1", "plain-h1", "h2", "h3", "auto":
	default:
		return nil, fmt.Errorf("chitanda: unsupported transport %q", c.Transport)
	}

	var protoUsers []*chitanda.User
	if len(c.Users) > 0 {
		if c.PSK != "" {
			return nil, fmt.Errorf("chitanda: psk and users cannot be configured together")
		}
		if len(c.Users) > server.MaxUserKeys {
			return nil, fmt.Errorf("chitanda: no more than %d users are supported", server.MaxUserKeys)
		}
		seenEmails := make(map[string]struct{})
		seenPSKs := make(map[string]struct{})
		for idx, u := range c.Users {
			if u == nil {
				return nil, fmt.Errorf("chitanda: user at index %d is nil", idx)
			}
			email := strings.TrimSpace(u.Email)
			if email == "" {
				return nil, fmt.Errorf("chitanda: user at index %d has empty email", idx)
			}
			lowerEmail := strings.ToLower(email)
			if _, exists := seenEmails[lowerEmail]; exists {
				return nil, fmt.Errorf("chitanda: duplicate user email %q", email)
			}
			seenEmails[lowerEmail] = struct{}{}

			if len(u.PSK) < 32 {
				return nil, fmt.Errorf("chitanda: user %q psk must contain at least 32 bytes", email)
			}
			if _, exists := seenPSKs[u.PSK]; exists {
				return nil, fmt.Errorf("chitanda: duplicate user psk for user %q", email)
			}
			seenPSKs[u.PSK] = struct{}{}

			protoUsers = append(protoUsers, &chitanda.User{
				Email: email,
				Psk:   u.PSK,
				Level: u.Level,
			})
		}
		if len(protoUsers) == 0 {
			return nil, fmt.Errorf("chitanda: no valid users configured in users list")
		}
	} else {
		if err := validateChitanda(c.PSK, c.Transport); err != nil {
			return nil, err
		}
	}
	if c.Path == "" {
		c.Path = "/api/v1/sync"
	}
	if err := client.ValidatePath(c.Path); err != nil {
		return nil, err
	}
	sid := c.ServerID
	if sid == "" {
		sid = c.ServerId
	}
	if sid == "" {
		sid = c.ServerHyphen
	}
	certFile := c.CertFile
	if certFile == "" {
		certFile = c.CertFileCamel
	}
	keyFile := c.KeyFile
	if keyFile == "" {
		keyFile = c.KeyFileCamel
	}
	if (certFile == "") != (keyFile == "") {
		return nil, fmt.Errorf("chitanda: cert_file and key_file must be supplied together")
	}
	return &chitanda.InboundConfig{
		Psk:        c.PSK,
		Path:       c.Path,
		Transport:  c.Transport,
		StrictSni:  c.StrictSNI,
		Fallback:   c.Fallback,
		ServerId:   sid,
		ReplayFile: c.ReplayFile,
		CertFile:   certFile,
		KeyFile:    keyFile,
		Users:      protoUsers,
	}, nil
}

type ChitandaOutboundConfig struct {
	Server             string `json:"server"`
	ServerName         string `json:"server_name"`
	PSK                string `json:"psk"`
	Path               string `json:"path"`
	Transport          string `json:"transport"`
	PoolSize           int32  `json:"pool_size"`
	AutoScale          bool   `json:"auto_scale"`
	MaxPoolSize        int32  `json:"max_pool_size"`
	ScaleUpThreshold   int32  `json:"scale_up_threshold"`
	ScaleDownIdle      int32  `json:"scale_down_idle"`
	Cooldown           int32  `json:"cooldown"`
	ServerID           string `json:"server_id"`
	ServerId           string `json:"serverId"`
	ServerHyphen       string `json:"server-id"`
	AllowInsecure      bool   `json:"allow_insecure"`
	AllowInsecureCamel bool   `json:"allowInsecure"`
}

func (c *ChitandaOutboundConfig) Build() (proto.Message, error) {
	if err := validateChitanda(c.PSK, c.Transport); err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(c.Server)
	if err != nil {
		return nil, fmt.Errorf("chitanda: server must be host:port: %w", err)
	}
	if c.ServerName == "" {
		c.ServerName = host
	}
	if c.Path == "" {
		c.Path = "/api/v1/sync"
	}
	if err := client.ValidateConfig(client.Config{Server: c.Server, ServerName: c.ServerName, PSK: []byte(c.PSK), Path: c.Path, TCPTransport: c.Transport}); err != nil {
		return nil, err
	}
	sid := c.ServerID
	if sid == "" {
		sid = c.ServerId
	}
	if sid == "" {
		sid = c.ServerHyphen
	}
	return &chitanda.OutboundConfig{
		Server:           c.Server,
		ServerName:       c.ServerName,
		Psk:              c.PSK,
		Path:             c.Path,
		Transport:        c.Transport,
		PoolSize:         c.PoolSize,
		AutoScale:        c.AutoScale,
		MaxPoolSize:      c.MaxPoolSize,
		ScaleUpThreshold: c.ScaleUpThreshold,
		ScaleDownIdle:    c.ScaleDownIdle,
		Cooldown:         c.Cooldown,
		ServerId:         sid,
		AllowInsecure:    c.AllowInsecure || c.AllowInsecureCamel,
	}, nil
}
