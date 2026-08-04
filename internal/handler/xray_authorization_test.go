package handler

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestManagedInboundDefinitionsFromInventoryKeepsStaleFencedTags(t *testing.T) {
	definitions := managedInboundDefinitionsFromInventory(
		map[string]inboundMutationFenceState{
			"managed": {Owner: "managed-inbound:server-a"},
			"pending": {
				Pending: &inboundMutationFencePending{Owner: "managed-inbound:server-b"},
			},
			"stale":   {Owner: "managed-inbound:server-c"},
			"unowned": {},
			"api":     {Owner: "managed-inbound:api"},
		},
		[]map[string]interface{}{
			{"tag": "unowned", "port": float64(10001)},
			{"tag": "managed", "port": float64(10002)},
			{"tag": "pending", "port": float64(10003)},
			// The primary config definition wins over a confdir duplicate.
			{"tag": "managed", "port": float64(10004)},
		},
	)

	if got, want := authorizationDefinitionTags(definitions), []string{"managed", "pending", "stale"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("selected tags=%v want %v", got, want)
	}
	if definitions[0].inbound["port"] != float64(10002) {
		t.Fatalf("managed definition did not retain the first durable config: %#v", definitions[0].inbound)
	}
	if definitions[2].inbound != nil {
		t.Fatalf("stale fenced tag unexpectedly gained a durable definition: %#v", definitions[2].inbound)
	}
}

func TestApplyXrayAuthorizationDoesNotStartStoppedExternalAfterGrant(t *testing.T) {
	handler := NewManageHandler("", "custom", "this-command-must-not-run")
	handler.SetXrayMode("external")
	handler.xrayAuthorized = false
	handler.xrayAuthorizationKnown = true

	definitions := []managedInboundDefinition{
		{tag: "managed", inbound: map[string]interface{}{"tag": "managed"}},
		{tag: "stale"},
	}
	handler.xrayAuthorizationInboundResolver = func() ([]managedInboundDefinition, error) {
		return definitions, nil
	}
	var applies []authorizationApplyCall
	handler.xrayAuthorizationRuntimeApply = func(_ context.Context, authorized bool, got []managedInboundDefinition) error {
		applies = append(applies, authorizationApplyCall{
			authorized: authorized,
			tags:       authorizationDefinitionTags(got),
		})
		return nil
	}

	if err := handler.ApplyXrayAuthorization(true); err != nil {
		t.Fatalf("reauthorize stopped external Xray: %v", err)
	}
	if got, want := applies, []authorizationApplyCall{{authorized: true, tags: []string{"managed", "stale"}}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime apply=%#v want %#v", got, want)
	}

	// A repeated authorized update retries runtime convergence but keeps the
	// manually stopped service untouched.
	if err := handler.ApplyXrayAuthorization(true); err != nil {
		t.Fatalf("repeat authorized update: %v", err)
	}
}

func TestApplyXrayAuthorizationDoesNotStartStoppedEmbeddedAfterGrant(t *testing.T) {
	handler := NewManageHandler("", "", "")
	handler.SetXrayMode("embedded")
	handler.xrayAuthorized = false
	handler.xrayAuthorizationKnown = true

	handler.xrayAuthorizationInboundResolver = func() ([]managedInboundDefinition, error) {
		return []managedInboundDefinition{{tag: "managed", inbound: map[string]interface{}{"tag": "managed"}}}, nil
	}
	runtimeCalls := 0
	handler.xrayAuthorizationRuntimeApply = func(_ context.Context, _ bool, _ []managedInboundDefinition) error {
		runtimeCalls++
		return nil
	}

	if err := handler.ApplyXrayAuthorization(true); err != nil {
		t.Fatalf("reauthorize stopped embedded Xray: %v", err)
	}
	if runtimeCalls != 1 {
		t.Fatalf("runtime apply calls=%d want 1", runtimeCalls)
	}
}

func TestApplyXrayAuthorizationDoesNotStartStoppedExternalOnInitialAuthorizedSync(t *testing.T) {
	handler := NewManageHandler("", "", "")
	handler.SetXrayMode("external")
	handler.xrayAuthorizationInboundResolver = func() ([]managedInboundDefinition, error) {
		return []managedInboundDefinition{{tag: "managed", inbound: map[string]interface{}{"tag": "managed"}}}, nil
	}
	runtimeCalls := 0
	handler.xrayAuthorizationRuntimeApply = func(_ context.Context, authorized bool, _ []managedInboundDefinition) error {
		if !authorized {
			t.Fatal("initial authorized sync attempted a disable")
		}
		runtimeCalls++
		return nil
	}

	if err := handler.ApplyXrayAuthorization(true); err != nil {
		t.Fatalf("initial authorized sync: %v", err)
	}
	if runtimeCalls != 1 {
		t.Fatalf("runtime calls=%d want 1", runtimeCalls)
	}
}

func TestReapplyUnauthorizedInboundRemovalAfterRuntimeStart(t *testing.T) {
	handler := NewManageHandler("", "", "")
	handler.xrayAuthorized = false
	handler.xrayAuthorizationKnown = true
	handler.xrayAuthorizationInboundResolver = func() ([]managedInboundDefinition, error) {
		return []managedInboundDefinition{{tag: "managed"}}, nil
	}
	var applies []bool
	handler.xrayAuthorizationRuntimeApply = func(_ context.Context, authorized bool, _ []managedInboundDefinition) error {
		applies = append(applies, authorized)
		return nil
	}

	handler.inboundsMu.Lock()
	err := handler.reapplyUnauthorizedInboundRemovalAfterRuntimeStartLocked()
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("reapply after runtime start: %v", err)
	}
	if got, want := applies, []bool{false}; !reflect.DeepEqual(got, want) {
		t.Fatalf("reapply calls=%v want %v", got, want)
	}

	handler.xrayAuthorized = true
	handler.inboundsMu.Lock()
	err = handler.reapplyUnauthorizedInboundRemovalAfterRuntimeStartLocked()
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("authorized post-start reconciliation: %v", err)
	}
	if got, want := applies, []bool{false}; !reflect.DeepEqual(got, want) {
		t.Fatalf("authorized post-start reconciliation unexpectedly changed inbounds: %v", got)
	}
}

func TestReplaceRuntimeInboundDoesNotResurrectFencedTagWhenUnauthorized(t *testing.T) {
	root := t.TempDir()
	handler := NewManageHandler("", "", "")
	handler.SetConfigPath(filepath.Join(root, "agent", "config.yaml"))
	if err := os.MkdirAll(filepath.Dir(handler.inboundMutationFencePath), 0755); err != nil {
		t.Fatalf("create inbound ownership fixture directory: %v", err)
	}
	if err := writeInboundMutationFenceFileAtomic(handler.inboundMutationFencePath, inboundMutationFenceFileFromStates(map[string]inboundMutationFenceState{
		"managed": {Owner: "managed-inbound:server-a"},
	})); err != nil {
		t.Fatalf("write inbound ownership fixture: %v", err)
	}
	handler.xrayAuthorized = false
	handler.xrayAuthorizationKnown = true

	handler.inboundsMu.Lock()
	err := handler.replaceRuntimeInbound(context.Background(), "managed", map[string]interface{}{"tag": "managed"})
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("unauthorized fenced runtime replacement: %v", err)
	}
	if !handler.inboundMutationFencesLoaded {
		t.Fatal("runtime replacement did not load ownership sidecar")
	}
	if got := handler.inboundMutationFences["managed"].Owner; got != "managed-inbound:server-a" {
		t.Fatalf("loaded owner=%q", got)
	}
}

type authorizationApplyCall struct {
	authorized bool
	tags       []string
}

func authorizationDefinitionTags(definitions []managedInboundDefinition) []string {
	tags := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		tags = append(tags, definition.tag)
	}
	return tags
}
