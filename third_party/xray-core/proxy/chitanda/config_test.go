package chitanda

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestConfigSerialization(t *testing.T) {
	inbound := &InboundConfig{
		Psk:        "test-psk-123456789012345678901234",
		Path:       "/test-path",
		Fallback:   "127.0.0.1:80",
		StrictSni:  "example.com",
		Transport:  "auto",
		ServerId:   "node-cluster-alpha",
		ReplayFile: "/tmp/replay.db",
	}

	data, err := proto.Marshal(inbound)
	if err != nil {
		t.Fatalf("marshal inbound failed: %v", err)
	}

	inboundDec := &InboundConfig{}
	if err := proto.Unmarshal(data, inboundDec); err != nil {
		t.Fatalf("unmarshal inbound failed: %v", err)
	}

	if inboundDec.ServerId != inbound.ServerId {
		t.Errorf("expected ServerId %q, got %q", inbound.ServerId, inboundDec.ServerId)
	}
	if inboundDec.ReplayFile != inbound.ReplayFile {
		t.Errorf("expected ReplayFile %q, got %q", inbound.ReplayFile, inboundDec.ReplayFile)
	}

	outbound := &OutboundConfig{
		Server:        "1.2.3.4:443",
		ServerName:    "status.example.com",
		Psk:           "test-psk-123456789012345678901234",
		Path:          "/test-path",
		Transport:     "h2",
		PoolSize:      8,
		ServerId:      "node-cluster-alpha",
		AllowInsecure: true,
	}

	outData, err := proto.Marshal(outbound)
	if err != nil {
		t.Fatalf("marshal outbound failed: %v", err)
	}

	outboundDec := &OutboundConfig{}
	if err := proto.Unmarshal(outData, outboundDec); err != nil {
		t.Fatalf("unmarshal outbound failed: %v", err)
	}

	if outboundDec.ServerId != outbound.ServerId {
		t.Errorf("expected ServerId %q, got %q", outbound.ServerId, outboundDec.ServerId)
	}
	if outboundDec.AllowInsecure != outbound.AllowInsecure {
		t.Errorf("expected AllowInsecure %v, got %v", outbound.AllowInsecure, outboundDec.AllowInsecure)
	}
}
