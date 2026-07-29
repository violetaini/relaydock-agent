package agent

import (
	"context"
	"net/http"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/config"
	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestOutboundRequestsUseLegacyCompatibleUserAgent(t *testing.T) {
	client := &Client{config: &config.Config{Token: "test-token"}}
	want := constants.AgentWireUserAgent()

	if got := client.wsHeaders().Get(constants.HeaderUserAgent); got != want {
		t.Fatalf("websocket User-Agent = %q, want %q", got, want)
	}

	request, err := client.newRequest(context.Background(), http.MethodGet, "https://control.example.test/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := request.Header.Get(constants.HeaderUserAgent); got != want {
		t.Fatalf("HTTP User-Agent = %q, want %q", got, want)
	}
}
