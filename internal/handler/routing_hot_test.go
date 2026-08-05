package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"
	routercommand "github.com/xtls/xray-core/app/router/command"
	"google.golang.org/grpc"
)

type recordingRoutingClient struct {
	routercommand.RoutingServiceClient
	request *routercommand.AddRuleRequest
	err     error
}

func (c *recordingRoutingClient) AddRule(_ context.Context, request *routercommand.AddRuleRequest, _ ...grpc.CallOption) (*routercommand.AddRuleResponse, error) {
	c.request = request
	if c.err != nil {
		return nil, c.err
	}
	return &routercommand.AddRuleResponse{}, nil
}

func TestApplyRoutingRulesHotReplacesRuntimeRules(t *testing.T) {
	client := &recordingRoutingClient{}
	routing := map[string]interface{}{
		"domainStrategy": "AsIs",
		"rules": []interface{}{
			map[string]interface{}{
				"type":        "field",
				"domain":      []interface{}{"example.com"},
				"outboundTag": "direct",
			},
		},
	}

	if err := applyRoutingRulesHot(context.Background(), client, routing); err != nil {
		t.Fatalf("apply hot routing: %v", err)
	}
	if client.request == nil || client.request.Config == nil {
		t.Fatal("RoutingService.AddRule did not receive a built router config")
	}
	if client.request.ShouldAppend {
		t.Fatal("hot routing must replace the active rule set, not append to it")
	}
}

func TestApplyRoutingRulesHotReturnsRuntimeError(t *testing.T) {
	client := &recordingRoutingClient{err: errors.New("routing service unavailable")}
	err := applyRoutingRulesHot(context.Background(), client, map[string]interface{}{"rules": []interface{}{}})
	if err == nil {
		t.Fatal("expected RoutingService error")
	}
}

func useStoppedXrayConfig(t *testing.T, config map[string]interface{}) (*ManageHandler, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	originalPaths := constants.DefaultXrayConfigPaths
	constants.DefaultXrayConfigPaths = []string{path}
	t.Cleanup(func() { constants.DefaultXrayConfigPaths = originalPaths })
	handler := NewManageHandler("test-token", "command", "false")
	handler.SetXrayMode("embedded")
	handler.xrayStatusResolver = func() *ServiceStatus {
		return &ServiceStatus{Installed: true, Running: false}
	}
	return handler, path
}

func TestSetHotPersistsStoppedXrayWithoutStartingIt(t *testing.T) {
	handler, configPath := useStoppedXrayConfig(t, map[string]interface{}{
		"inbounds": []interface{}{},
		"routing":  map[string]interface{}{"rules": []interface{}{}},
	})
	body := `{"action":"set_hot","routing":{"rules":[{"type":"field","domain":["example.com"],"outboundTag":"direct"}]}}`
	request := httptest.NewRequest(http.MethodPost, "/api/child/routing", strings.NewReader(body))
	response := httptest.NewRecorder()

	handler.manageRouting(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"runtime_applied":false`) {
		t.Fatalf("expected deferred runtime response, got %s", response.Body.String())
	}
	if handler.embeddedXray != nil {
		t.Fatal("stopped Xray was started by a hot routing update")
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "example.com") {
		t.Fatalf("routing was not persisted: %s", data)
	}
}

func TestBatchRoutingPersistsStoppedXrayWithoutRestart(t *testing.T) {
	handler, _ := useStoppedXrayConfig(t, map[string]interface{}{
		"inbounds": []interface{}{},
		"routing": map[string]interface{}{
			"rules": []interface{}{map[string]interface{}{
				"type":        "field",
				"marktag":     "managed-route",
				"user":        []interface{}{"admin"},
				"outboundTag": "proxy-out",
			}},
		},
	})
	body := `{"routing_user_additions":[{"marktag":"managed-route","user_email":"alice"}]}`
	request := httptest.NewRequest(http.MethodPost, "/api/child/batch-apply", strings.NewReader(body))
	request.Header.Set(constants.HeaderUserAgent, constants.AgentUserAgent)
	request.Header.Set(constants.HeaderAuthorization, constants.BearerPrefix+"test-token")
	response := httptest.NewRecorder()

	handler.HandleBatchApply(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "runtime apply deferred") {
		t.Fatalf("expected deferred runtime response, got %s", response.Body.String())
	}
	if handler.embeddedXray != nil {
		t.Fatal("stopped Xray was started by a batch routing update")
	}
}
