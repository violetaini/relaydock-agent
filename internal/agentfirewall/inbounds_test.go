package agentfirewall

import (
	"reflect"
	"testing"
)

func TestInboundTransportsChitanda(t *testing.T) {
	got := inboundTransports(map[string]interface{}{
		"protocol": "chitanda",
		"port":     float64(567),
	})
	want := []string{"tcp", "udp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("inboundTransports(chitanda) = %v, want %v", got, want)
	}
}
