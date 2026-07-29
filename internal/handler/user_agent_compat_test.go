package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestInboundAuthenticationAcceptsRollingUserAgents(t *testing.T) {
	const token = "test-token"
	manage := NewManageHandler(token, "", "")
	pull := NewAPIHandler(nil, token)
	warp := NewWarpHandler(token, nil, manage)

	checks := map[string]func(*http.Request) bool{
		"management": manage.authenticate,
		"pull":       pull.authenticate,
		"silent": func(request *http.Request) bool {
			return silentAuthenticate(request, token)
		},
		"warp": warp.auth,
	}

	userAgents := map[string]string{
		"legacy wire": constants.AgentWireUserAgent(),
		"RelayDock":   constants.AgentUserAgent,
	}
	for userAgentName, userAgent := range userAgents {
		for checkName, check := range checks {
			t.Run(userAgentName+"/"+checkName, func(t *testing.T) {
				request := authenticatedUserAgentRequest(token, userAgent)
				if !check(request) {
					t.Fatalf("%s authentication rejected %s User-Agent", checkName, userAgentName)
				}
			})
		}
	}
}

func TestInboundAuthenticationRejectsUnknownUserAgent(t *testing.T) {
	request := authenticatedUserAgentRequest("test-token", "other-agent/0.1")
	if NewManageHandler("test-token", "", "").authenticate(request) {
		t.Fatal("management authentication accepted an unknown User-Agent")
	}
}

func authenticatedUserAgentRequest(token, userAgent string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(constants.HeaderUserAgent, userAgent)
	request.Header.Set(constants.HeaderAuthorization, constants.BearerPrefix+token)
	return request
}
