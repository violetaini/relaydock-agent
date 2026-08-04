package embedded

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestValidateConfigProtocolsRejectsDisabledProtocol(t *testing.T) {
	tests := []string{
		`{"inbounds":[{"protocol":"snell"}]}`,
		`{"outbounds":[{"protocol":" SnElL "}]}`,
		`{"protocol":"snell","settings":{}}`,
	}
	for _, raw := range tests {
		if err := ValidateConfigProtocols([]byte(raw)); err == nil || !strings.Contains(err.Error(), "disabled") {
			t.Fatalf("ValidateConfigProtocols(%s) error = %v, want disabled protocol error", raw, err)
		}
	}
}

func TestValidateConfigProtocolsAllowsOtherProtocolFields(t *testing.T) {
	raw := []byte(`{"inbounds":[{"protocol":"vless"}],"routing":{"rules":[{"protocol":["bittorrent"]}]}}`)
	if err := ValidateConfigProtocols(raw); err != nil {
		t.Fatalf("ValidateConfigProtocols rejected an unrelated protocol field: %v", err)
	}
}

func TestSuppressConfiguredInboundsRemovesOnlySelectedTags(t *testing.T) {
	original := []byte(`{
  "inbounds": [
    {"tag": "managed", "protocol": "vless", "port": 443},
    {"tag": "user-owned", "protocol": "socks", "port": 1080},
    {"tag": "api", "protocol": "dokodemo-door", "port": 10085}
  ],
  "outbounds": [{"protocol": "freedom"}]
}`)

	filtered, err := suppressConfiguredInbounds(original, map[string]struct{}{"managed": {}})
	if err != nil {
		t.Fatalf("suppress inbounds: %v", err)
	}
	if strings.Contains(string(filtered), `"tag":"managed"`) {
		t.Fatalf("filtered config still contains managed inbound: %s", filtered)
	}

	var config struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(filtered, &config); err != nil {
		t.Fatalf("decode filtered config: %v", err)
	}
	got := make([]string, 0, len(config.Inbounds))
	for _, inbound := range config.Inbounds {
		got = append(got, inbound.Tag)
	}
	if want := []string{"user-owned", "api"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("remaining inbound tags = %v, want %v", got, want)
	}
	if !strings.Contains(string(original), `"tag": "managed"`) {
		t.Fatal("suppression mutated the durable source buffer")
	}
}

func TestSuppressConfiguredInboundsRejectsMalformedInboundArray(t *testing.T) {
	_, err := suppressConfiguredInbounds([]byte(`{"inbounds": {}}`), map[string]struct{}{"managed": {}})
	if err == nil || !strings.Contains(err.Error(), "inbounds") {
		t.Fatalf("malformed inbounds error = %v, want inbounds parse error", err)
	}
}
