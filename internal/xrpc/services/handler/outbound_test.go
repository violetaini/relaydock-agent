package handler

import (
	"context"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"

	"github.com/xtls/xray-core/app/proxyman/command"
	xhttp "github.com/xtls/xray-core/proxy/http"
	"google.golang.org/grpc"
)

type recordingHandlerServiceClient struct {
	command.HandlerServiceClient
	request *command.AddOutboundRequest
}

func (c *recordingHandlerServiceClient) AddOutbound(_ context.Context, request *command.AddOutboundRequest, _ ...grpc.CallOption) (*command.AddOutboundResponse, error) {
	c.request = request
	return &command.AddOutboundResponse{}, nil
}

func TestAddHTTPOutboundUsesLegacyCompatibleUserAgent(t *testing.T) {
	client := &recordingHandlerServiceClient{}
	if err := AddHTTPOutbound(context.Background(), client, "test-http"); err != nil {
		t.Fatal(err)
	}
	if client.request == nil || client.request.Outbound == nil || client.request.Outbound.ProxySettings == nil {
		t.Fatal("AddHTTPOutbound did not submit proxy settings")
	}

	instance, err := client.request.Outbound.ProxySettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	config, ok := instance.(*xhttp.ClientConfig)
	if !ok {
		t.Fatalf("proxy settings type = %T, want *http.ClientConfig", instance)
	}

	for _, header := range config.Header {
		if header.Key == "User-Agent" {
			if header.Value != constants.AgentWireUserAgent() {
				t.Fatalf("xRPC outbound User-Agent = %q, want %q", header.Value, constants.AgentWireUserAgent())
			}
			return
		}
	}
	t.Fatal("xRPC outbound has no User-Agent header")
}
