package constants

import "testing"

func TestAgentUserAgentCompatibility(t *testing.T) {
	wantWire := "miao" + "miao" + "wu" + "x/0.1"
	if got := AgentWireUserAgent(); got != wantWire {
		t.Fatalf("AgentWireUserAgent() = %q, want %q", got, wantWire)
	}
	if AgentWireUserAgent() == AgentUserAgent {
		t.Fatal("wire and RelayDock user agents must remain distinct during migration")
	}

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "legacy wire", value: AgentWireUserAgent(), want: true},
		{name: "RelayDock", value: AgentUserAgent, want: true},
		{name: "empty", value: "", want: false},
		{name: "unknown", value: "other-agent/0.1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAgentUserAgent(tt.value); got != tt.want {
				t.Fatalf("IsAgentUserAgent(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
