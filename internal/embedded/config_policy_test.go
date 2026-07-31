package embedded

import (
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
