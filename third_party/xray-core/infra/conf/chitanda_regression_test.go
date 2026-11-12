package conf

import (
	"encoding/json"
	"github.com/xtls/xray-core/proxy/chitanda"
	"testing"
)

func TestReviewChitandaAllowInsecure(t *testing.T) {
	var c ChitandaOutboundConfig
	if e := json.Unmarshal([]byte(`{"server":"example.com:443","psk":"local-review-only-test-key-32-bytes","allow_insecure":true}`), &c); e != nil {
		t.Fatal(e)
	}
	m, e := c.Build()
	if e != nil {
		t.Fatal(e)
	}
	if !m.(*chitanda.OutboundConfig).AllowInsecure {
		t.Error("documented allow_insecure:true lost by JSON config builder")
	}
}
