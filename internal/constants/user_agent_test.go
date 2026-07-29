package constants

import "testing"

func TestAgentUserAgentValidation(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
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
