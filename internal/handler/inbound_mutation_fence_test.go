package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInboundMutationFenceRejectsLateAddAfterPersistedRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	configPath := inboundMutationFenceTestConfigPath(path)
	writeInboundMutationTestConfig(t, configPath)
	first := newInboundMutationFenceTestHandler(path)
	first.inboundsMu.Lock()
	skip, _, err := first.beginInboundMutationLocked("remove", &InboundRequest{Tag: "tunnel-race-h0", MutationID: "operation-old"})
	first.inboundsMu.Unlock()
	if err != nil || skip {
		t.Fatalf("begin remove skip=%v err=%v", skip, err)
	}

	// Simulate a new Agent process receiving the delayed add after the remove
	// already acknowledged. The sidecar tombstone must still reject it.
	second := newInboundMutationFenceTestHandler(path)
	second.inboundsMu.Lock()
	_, err = second.beginInboundAddMutationLocked(&InboundRequest{
		MutationID: "operation-old",
		Inbound:    map[string]interface{}{"tag": "tunnel-race-h0"},
	}, configPath, nil)
	second.inboundsMu.Unlock()
	if err == nil {
		t.Fatal("late add unexpectedly passed the persisted remove fence")
	}

	second.inboundsMu.Lock()
	intended := map[string]interface{}{"tag": "tunnel-race-h0"}
	transaction, err := second.beginInboundAddMutationLocked(&InboundRequest{
		MutationID: "operation-new",
		Inbound:    intended,
	}, configPath, nil)
	if err == nil {
		writeInboundMutationTestConfig(t, configPath, intended)
		err = second.commitInboundMutationLocked(transaction)
	}
	skip, _, removeErr := second.beginInboundMutationLocked("remove", &InboundRequest{Tag: "tunnel-race-h0", MutationID: "operation-old"})
	second.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("new mutation was rejected: %v", err)
	}
	if removeErr != nil || !skip {
		t.Fatalf("old remove must not delete newer mutation: skip=%v err=%v", skip, removeErr)
	}
}

func TestInboundMutationFenceRejectsUnfencedRemoveOfOwnedTag(t *testing.T) {
	handler := newInboundMutationFenceTestHandler(filepath.Join(t.TempDir(), "inbound-fences.json"))
	seedInboundMutationOwner(t, handler, "same-tag", "generation-new")
	handler.inboundsMu.Lock()
	_, _, removeErr := handler.beginInboundMutationLocked("remove", &InboundRequest{Tag: "same-tag"})
	handler.inboundsMu.Unlock()
	if removeErr == nil {
		t.Fatal("empty mutation_id unexpectedly removed an owned tag")
	}
}

func TestInboundMutationFenceAllowsLegacyRemoveWithoutOwner(t *testing.T) {
	handler := newInboundMutationFenceTestHandler(filepath.Join(t.TempDir(), "inbound-fences.json"))
	handler.inboundsMu.Lock()
	skip, _, err := handler.beginInboundMutationLocked("remove", &InboundRequest{Tag: "legacy-tag"})
	handler.inboundsMu.Unlock()
	if err != nil || skip {
		t.Fatalf("legacy unfenced remove skip=%v err=%v", skip, err)
	}
}

func TestInboundMutationFenceConditionalReplacementCAS(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "xray-config.json")
	previousInbound := map[string]interface{}{"tag": "legacy-wireguard", "port": float64(51820)}
	intendedInbound := map[string]interface{}{"tag": "legacy-wireguard", "port": float64(51821)}
	writeInboundMutationTestConfig(t, configPath, previousInbound)
	previousDigest, err := canonicalInboundMutationDigest(previousInbound)
	if err != nil {
		t.Fatal(err)
	}
	emptyOwner := ""

	handler := newInboundMutationFenceTestHandler(filepath.Join(directory, "inbound-fences.json"))
	handler.inboundsMu.Lock()
	transaction, err := handler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID:            "managed-wireguard:legacy-generation",
		ExpectedMutationOwner: &emptyOwner,
		ExpectedInboundDigest: previousDigest,
		Inbound:               intendedInbound,
	}, configPath, previousInbound)
	if err == nil {
		err = handler.rollbackInboundMutationLocked(transaction)
	}
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("matching conditional replacement failed: %v", err)
	}

	currentOwner := "managed-wireguard:current-generation"
	ownedHandler := loadedInboundMutationFenceTestHandler(
		filepath.Join(directory, "owned-inbound-fences.json"),
		"legacy-wireguard",
		currentOwner,
	)
	ownedHandler.inboundsMu.Lock()
	ownedTransaction, ownedErr := ownedHandler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID:            currentOwner,
		ExpectedMutationOwner: &currentOwner,
		ExpectedInboundDigest: previousDigest,
		Inbound:               intendedInbound,
	}, configPath, previousInbound)
	if ownedErr == nil {
		ownedErr = ownedHandler.rollbackInboundMutationLocked(ownedTransaction)
	}
	ownedHandler.inboundsMu.Unlock()
	if ownedErr != nil {
		t.Fatalf("matching owned conditional replacement failed: %v", ownedErr)
	}

	ownerHandler := loadedInboundMutationFenceTestHandler(
		filepath.Join(directory, "owner-inbound-fences.json"),
		"legacy-wireguard",
		"managed-wireguard:newer-generation",
	)
	ownerHandler.inboundsMu.Lock()
	_, ownerErr := ownerHandler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID:            "managed-wireguard:legacy-generation",
		ExpectedMutationOwner: &emptyOwner,
		ExpectedInboundDigest: previousDigest,
		Inbound:               intendedInbound,
	}, configPath, previousInbound)
	ownerHandler.inboundsMu.Unlock()
	if ownerErr == nil || !strings.Contains(ownerErr.Error(), "owner changed") {
		t.Fatalf("changed owner was not rejected: %v", ownerErr)
	}

	digestHandler := newInboundMutationFenceTestHandler(filepath.Join(directory, "digest-inbound-fences.json"))
	digestHandler.inboundsMu.Lock()
	_, digestErr := digestHandler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID:            "managed-wireguard:legacy-generation",
		ExpectedMutationOwner: &emptyOwner,
		ExpectedInboundDigest: strings.Repeat("0", 64),
		Inbound:               intendedInbound,
	}, configPath, previousInbound)
	digestHandler.inboundsMu.Unlock()
	if digestErr == nil || !strings.Contains(digestErr.Error(), "changed before conditional replacement") {
		t.Fatalf("changed inbound digest was not rejected: %v", digestErr)
	}

	digestOnlyHandler := newInboundMutationFenceTestHandler(filepath.Join(directory, "digest-only-inbound-fences.json"))
	digestOnlyHandler.inboundsMu.Lock()
	_, digestOnlyErr := digestOnlyHandler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID:            "managed-wireguard:legacy-generation",
		ExpectedInboundDigest: previousDigest,
		Inbound:               intendedInbound,
	}, configPath, previousInbound)
	digestOnlyHandler.inboundsMu.Unlock()
	if digestOnlyErr == nil || !strings.Contains(digestOnlyErr.Error(), "requires an expected mutation owner") {
		t.Fatalf("digest without expected owner was not rejected: %v", digestOnlyErr)
	}
}

func TestInboundMutationFenceRequiresExactSentinelOwner(t *testing.T) {
	handler := loadedInboundMutationFenceTestHandler(
		filepath.Join(t.TempDir(), "inbound-fences.json"),
		"sentinel-tag",
		unfencedInboundMutationOwner,
	)
	if _, _, err := handler.beginInboundMutationLocked("remove", &InboundRequest{Tag: "sentinel-tag"}); err == nil {
		t.Fatal("empty mutation_id unexpectedly removed sentinel-owned inbound")
	}
	skip, _, err := handler.beginInboundMutationLocked("remove", &InboundRequest{
		Tag:        "sentinel-tag",
		MutationID: unfencedInboundMutationOwner,
	})
	if err != nil || skip {
		t.Fatalf("exact sentinel owner remove skip=%v err=%v", skip, err)
	}
}

func TestApplyInboundAddMutationRestoresPreviousFenceOnEveryFailurePhase(t *testing.T) {
	for _, phase := range []string{"grpc", "config", "firewall"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inbound-fences.json")
			handler := newInboundMutationFenceTestHandler(path)
			seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
			configPath := inboundMutationFenceTestConfigPath(path)
			previous := readInboundMutationTestConfig(t, configPath, "same-tag")

			handler.inboundsMu.Lock()
			err := handler.applyInboundAddMutationLocked(&InboundRequest{
				MutationID: "generation-new",
				Inbound:    map[string]interface{}{"tag": "same-tag"},
			}, configPath, previous, func() error {
				return errors.New("synthetic " + phase + " failure")
			})
			handler.inboundsMu.Unlock()
			if err == nil {
				t.Fatalf("%s failure unexpectedly succeeded", phase)
			}
			assertInboundMutationOwnerRestored(t, path, "same-tag", "generation-old", "generation-new")
		})
	}
}

func TestApplyInboundAddMutationCommitsAfterAllPhasesSucceed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
	configPath := inboundMutationFenceTestConfigPath(path)
	previous := readInboundMutationTestConfig(t, configPath, "same-tag")
	intended := map[string]interface{}{"tag": "same-tag", "port": float64(2443)}

	handler.inboundsMu.Lock()
	err := handler.applyInboundAddMutationLocked(&InboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous, func() error {
		writeInboundMutationTestConfig(t, configPath, intended)
		return nil
	})
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("apply successful add: %v", err)
	}

	reloaded := newInboundMutationFenceTestHandler(path)
	if err := reloaded.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatalf("reload mutation fence: %v", err)
	}
	if got := reloaded.inboundMutationFences["same-tag"].Owner; got != "generation-new" {
		t.Fatalf("owner=%q want generation-new", got)
	}
}

func TestPendingInboundMutationBeforeConfigWriteRestoresPreviousOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
	configPath := inboundMutationFenceTestConfigPath(path)
	previous := readInboundMutationTestConfig(t, configPath, "same-tag")
	intended := map[string]interface{}{"tag": "same-tag", "port": float64(2443)}

	handler.inboundsMu.Lock()
	_, err := handler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous)
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("reserve pending mutation: %v", err)
	}

	// Simulate a process crash before the config phase: only the pending WAL was
	// written. Inventory stays fail-closed until runtime convergence, then the
	// previous committed owner is restored from the durable config.
	reloaded := newInboundMutationFenceTestHandler(path)
	if err := reloaded.ensureInboundMutationFencesLocked(); err == nil {
		t.Fatal("pre-config pending owner was exposed before runtime convergence")
	}
	reloaded.inboundMutationRuntimeConverge = func() error { return nil }
	if err := reloaded.RecoverInboundMutationFences(); err != nil {
		t.Fatalf("recover pre-config crash after runtime convergence: %v", err)
	}
	assertInboundMutationOwnerInMemory(t, reloaded, "same-tag", "generation-old")
	if reloaded.inboundMutationFences["same-tag"].Pending != nil {
		t.Fatal("pre-config recovery left pending WAL behind")
	}
}

func TestPendingInboundMutationAfterConfigWriteCommitsNewOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
	configPath := inboundMutationFenceTestConfigPath(path)
	previous := readInboundMutationTestConfig(t, configPath, "same-tag")
	intended := map[string]interface{}{"tag": "same-tag", "port": float64(2443)}

	handler.inboundsMu.Lock()
	_, err := handler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous)
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("reserve pending mutation: %v", err)
	}
	writeInboundMutationTestConfig(t, configPath, intended)

	// Simulate a crash after the durable config rename but before the fence
	// commit. The restarted Agent must not publish it until runtime has reloaded
	// the config, then commits the new generation from its digest.
	reloaded := newInboundMutationFenceTestHandler(path)
	applyCount := 0
	var appliedTag string
	var appliedInbound map[string]interface{}
	var appliedPresent bool
	reloaded.inboundMutationRuntimeApply = func(
		_ context.Context,
		tag string,
		inbound map[string]interface{},
		present bool,
	) error {
		applyCount++
		appliedTag = tag
		appliedInbound = inbound
		appliedPresent = present
		return nil
	}
	if err := reloaded.ensureInboundMutationFencesLocked(); err == nil {
		t.Fatal("post-config pending owner was exposed before runtime convergence")
	}
	reloaded.inboundMutationRuntimeConverge = func() error {
		return errors.New("synthetic external Xray restart failure")
	}
	if err := reloaded.RecoverInboundMutationFences(); err == nil {
		t.Fatal("post-config owner was committed after runtime convergence failed")
	}
	if applyCount != 0 {
		t.Fatalf("runtime inbound was applied before the Xray restart succeeded: count=%d", applyCount)
	}
	if _, err := reloaded.annotateInboundMutationInventoryLocked([]map[string]interface{}{{"tag": "same-tag"}}); err == nil {
		t.Fatal("inventory exposed post-config owner after runtime convergence failed")
	}
	reloaded.inboundMutationRuntimeConverge = func() error { return nil }
	if err := reloaded.RecoverInboundMutationFences(); err != nil {
		t.Fatalf("recover post-config crash after runtime convergence: %v", err)
	}
	if applyCount != 1 || appliedTag != "same-tag" || !appliedPresent {
		t.Fatalf("runtime apply=(count=%d tag=%q present=%v), want exact intended inbound", applyCount, appliedTag, appliedPresent)
	}
	if got := fmt.Sprint(appliedInbound["port"]); got != "2443" {
		t.Fatalf("runtime applied port=%v want 2443", got)
	}
	assertInboundMutationOwnerInMemory(t, reloaded, "same-tag", "generation-new")
	if reloaded.inboundMutationFences["same-tag"].Pending != nil {
		t.Fatal("post-config recovery left pending WAL behind")
	}
}

func TestPendingInboundRecoveryDoesNotStartStoppedXray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
	configPath := inboundMutationFenceTestConfigPath(path)
	previous := readInboundMutationTestConfig(t, configPath, "same-tag")
	intended := map[string]interface{}{"tag": "same-tag", "port": float64(2443)}

	handler.inboundsMu.Lock()
	_, err := handler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous)
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("reserve pending mutation: %v", err)
	}
	writeInboundMutationTestConfig(t, configPath, intended)

	reloaded := newInboundMutationFenceTestHandler(path)
	reloaded.xrayStatusResolver = func() *ServiceStatus {
		return &ServiceStatus{Installed: true, Running: false}
	}
	err = reloaded.RecoverInboundMutationFences()
	if err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Fatalf("stopped Xray recovery error = %v, want deferred recovery", err)
	}
	if reloaded.inboundMutationFences["same-tag"].Pending == nil {
		t.Fatal("stopped Xray recovery discarded the pending fence")
	}
	if _, err := reloaded.annotateInboundMutationInventoryLocked([]map[string]interface{}{{"tag": "same-tag"}}); err == nil {
		t.Fatal("stopped Xray recovery published the pending owner")
	}
}

func TestPendingInboundRecoveryUsesRuntimeApplyWithoutRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
	configPath := inboundMutationFenceTestConfigPath(path)
	previous := readInboundMutationTestConfig(t, configPath, "same-tag")
	intended := map[string]interface{}{"tag": "same-tag", "port": float64(2443)}

	handler.inboundsMu.Lock()
	_, err := handler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous)
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("reserve pending mutation: %v", err)
	}
	writeInboundMutationTestConfig(t, configPath, intended)

	restartMarker := filepath.Join(t.TempDir(), "xray-restarted")
	reloaded := newInboundMutationFenceTestHandler(path)
	reloaded.restartMethod = "custom"
	reloaded.restartCommand = "printf restarted > " + restartMarker
	reloaded.xrayStatusResolver = func() *ServiceStatus {
		return &ServiceStatus{Installed: true, Running: true}
	}
	applyCount := 0
	reloaded.inboundMutationRuntimeApply = func(_ context.Context, tag string, inbound map[string]interface{}, present bool) error {
		applyCount++
		if tag != "same-tag" || !present || fmt.Sprint(inbound["port"]) != "2443" {
			t.Fatalf("unexpected runtime convergence tag=%q present=%v inbound=%#v", tag, present, inbound)
		}
		return nil
	}

	if err := reloaded.RecoverInboundMutationFences(); err != nil {
		t.Fatalf("recover pending inbound mutation: %v", err)
	}
	if applyCount != 1 {
		t.Fatalf("runtime apply count=%d, want 1", applyCount)
	}
	if _, err := os.Stat(restartMarker); !os.IsNotExist(err) {
		t.Fatalf("pending recovery unexpectedly restarted Xray: %v", err)
	}
	if reloaded.inboundMutationFences["same-tag"].Pending != nil {
		t.Fatal("pending fence was not resolved after runtime convergence")
	}
}

func TestPendingInboundMutationFailsClosedWhenConfigPathsDisagree(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
	configPath := inboundMutationFenceTestConfigPath(path)
	previous := readInboundMutationTestConfig(t, configPath, "same-tag")
	intended := map[string]interface{}{"tag": "same-tag", "port": float64(2443)}

	handler.inboundsMu.Lock()
	_, err := handler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous)
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("reserve pending mutation: %v", err)
	}

	alternateConfigPath := filepath.Join(directory, "alternate-xray-config.json")
	writeInboundMutationTestConfig(t, alternateConfigPath, intended)
	reloaded := newInboundMutationFenceTestHandler(path)
	reloaded.inboundMutationConfigPathResolver = func() string { return alternateConfigPath }
	reloaded.inboundMutationRuntimeConverge = func() error { return nil }
	if err := reloaded.RecoverInboundMutationFences(); err == nil || !strings.Contains(err.Error(), "config paths disagree") {
		t.Fatalf("disagreeing durable configs did not fail closed: %v", err)
	}
}

func TestPendingInboundMutationBlocksClientAndBatchConfigWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	handler.inboundMutationFencesLoaded = true
	handler.inboundMutationRecoveryReady = false
	handler.inboundMutationFences["same-tag"] = inboundMutationFenceState{
		Owner: "generation-old",
		Pending: &inboundMutationFencePending{
			Owner:         "generation-new",
			PreviousOwner: "generation-old",
		},
	}

	for _, action := range []string{"add-client", "remove-client", "add-sniffing-exclude"} {
		t.Run(action, func(t *testing.T) {
			body := fmt.Sprintf(`{"action":%q,"tag":"same-tag","client":{"id":"client-a"},"domains":["example.com"]}`, action)
			req := httptest.NewRequest(http.MethodPost, "/manage/inbounds", strings.NewReader(body))
			response := httptest.NewRecorder()
			handler.manageInbound(response, req)
			if response.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s want conflict", response.Code, response.Body.String())
			}
		})
	}

	batchReq := httptest.NewRequest(http.MethodPost, "/manage/batch", strings.NewReader(`{"inbound_clients":[{"tag":"same-tag","client":{"id":"client-a"}}]}`))
	batchReq.Header.Set("X-WS-RPC", "1")
	batchReq.RemoteAddr = "ws-rpc"
	batchResponse := httptest.NewRecorder()
	handler.HandleBatchApply(batchResponse, batchReq)
	if batchResponse.Code != http.StatusConflict {
		t.Fatalf("batch status=%d body=%s want conflict", batchResponse.Code, batchResponse.Body.String())
	}

	configMutations := []struct {
		name string
		body string
		call func(http.ResponseWriter, *http.Request)
	}{
		{name: "whole-config", body: `{"config":"{}"}`, call: handler.setXrayConfig},
		{name: "config-fragment", body: `{"file":"pending.json","content":"{}"}`, call: handler.saveXrayConfigFile},
		{name: "system-config", body: `{}`, call: handler.updateXraySystemConfig},
		{name: "outbound", body: `{"action":"add","outbound":{"tag":"direct"}}`, call: handler.manageOutbound},
		{name: "routing", body: `{"action":"set","routing":{}}`, call: handler.manageRouting},
	}
	for _, mutation := range configMutations {
		t.Run(mutation.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/manage/config", strings.NewReader(mutation.body))
			response := httptest.NewRecorder()
			mutation.call(response, req)
			if response.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s want conflict", response.Code, response.Body.String())
			}
		})
	}

	if result := handler.EnsureXrayConfig(); result.Error == "" {
		t.Fatal("Xray config auto-update was not blocked while inbound recovery was pending")
	}
}

func TestXrayLifecycleWaitsForInboundTransaction(t *testing.T) {
	handler := newInboundMutationFenceTestHandler(filepath.Join(t.TempDir(), "inbound-fences.json"))
	handler.restartMethod = "custom"
	handler.restartCommand = "true"

	handler.inboundsMu.Lock()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- handler.RestartXray()
	}()
	<-started
	select {
	case err := <-done:
		handler.inboundsMu.Unlock()
		t.Fatalf("Xray restart bypassed the inbound transaction lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	handler.inboundsMu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serialized Xray restart failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serialized Xray restart did not resume after inbound transaction completed")
	}
}

func TestPendingInboundMutationMismatchFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
	configPath := inboundMutationFenceTestConfigPath(path)
	previous := readInboundMutationTestConfig(t, configPath, "same-tag")
	intended := map[string]interface{}{"tag": "same-tag", "port": float64(2443)}

	handler.inboundsMu.Lock()
	_, err := handler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous)
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("reserve pending mutation: %v", err)
	}
	writeInboundMutationTestConfig(t, configPath, map[string]interface{}{
		"tag": "same-tag", "port": float64(6553),
	})

	reloaded := newInboundMutationFenceTestHandler(path)
	reloaded.inboundMutationRuntimeConverge = func() error { return nil }
	if err := reloaded.RecoverInboundMutationFences(); err == nil {
		t.Fatal("mismatched durable config unexpectedly published an owner")
	}
	if _, err := reloaded.annotateInboundMutationInventoryLocked([]map[string]interface{}{{"tag": "same-tag"}}); err == nil {
		t.Fatal("inventory exposed authoritative ownership while recovery was ambiguous")
	}
}

func TestPreparedInboundDigestMatchesDeduplicatedConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "xray.json")
	first := map[string]interface{}{
		"tag": "same-tag", "protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{"id": "old-a"}}},
	}
	duplicate := map[string]interface{}{
		"tag": "same-tag", "protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{"id": "old-b"}}},
	}
	writeInboundMutationTestConfig(t, configPath, first, duplicate)
	snapshot, err := captureConfigFile(configPath)
	if err != nil {
		t.Fatalf("snapshot duplicate config: %v", err)
	}
	request := map[string]interface{}{
		"tag": "same-tag", "protocol": "vless",
		"settings": map[string]interface{}{"clients": []interface{}{map[string]interface{}{"id": "new-c"}}},
	}
	prepared, err := prepareInboundForPersistence(snapshot, request)
	if err != nil {
		t.Fatalf("prepare inbound: %v", err)
	}
	intendedDigest, err := canonicalInboundMutationDigest(prepared)
	if err != nil {
		t.Fatalf("digest prepared inbound: %v", err)
	}
	handler := newInboundMutationFenceTestHandler(filepath.Join(t.TempDir(), "fence.json"))
	if err := handler.persistInboundAtPath(configPath, prepared); err != nil {
		t.Fatalf("persist prepared inbound: %v", err)
	}
	actualDigest, present, err := inboundMutationDigestFromConfig(configPath, "same-tag")
	if err != nil {
		t.Fatalf("digest persisted inbound: %v", err)
	}
	if !present || actualDigest != intendedDigest {
		t.Fatalf("persisted digest=%q present=%v want %q", actualDigest, present, intendedDigest)
	}
}

func TestUnfencedAddIsRejectedAfterFenceHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
	configPath := inboundMutationFenceTestConfigPath(path)
	previous := readInboundMutationTestConfig(t, configPath, "same-tag")

	called := false
	handler.inboundsMu.Lock()
	err := handler.applyInboundAddMutationLocked(&InboundRequest{
		Inbound: map[string]interface{}{"tag": "same-tag"},
	}, configPath, previous, func() error {
		called = true
		return nil
	})
	handler.inboundsMu.Unlock()
	if err == nil {
		t.Fatal("unfenced replacement unexpectedly succeeded")
	}
	if called {
		t.Fatal("inbound apply ran without a mutation ID after fence history")
	}
	assertInboundMutationOwnerInMemory(t, handler, "same-tag", "generation-old")
}

func TestUnfencedAddRemainsCompatibleForNeverFencedLegacyTag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	called := false
	handler.inboundsMu.Lock()
	err := handler.applyInboundAddMutationLocked(&InboundRequest{
		Inbound: map[string]interface{}{"tag": "legacy-tag"},
	}, inboundMutationFenceTestConfigPath(path), nil, func() error {
		called = true
		return nil
	})
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("legacy unfenced add: %v", err)
	}
	if !called {
		t.Fatal("legacy inbound apply did not run")
	}
	if state, exists := handler.inboundMutationFences["legacy-tag"]; exists && state.Owner != "" {
		t.Fatalf("legacy add unexpectedly gained owner %q", state.Owner)
	}
}

func TestInboundMutationStateRollsBackWhenSidecarPersistenceFails(t *testing.T) {
	root := t.TempDir()
	blockedDirectory := filepath.Join(root, "blocked")
	if err := os.WriteFile(blockedDirectory, []byte("not a directory"), 0600); err != nil {
		t.Fatalf("create blocked path: %v", err)
	}
	missingPath := filepath.Join(blockedDirectory, "inbound-fences.json")

	t.Run("add reservation", func(t *testing.T) {
		handler := loadedInboundMutationFenceTestHandler(missingPath, "same-tag", "generation-old")
		_, err := handler.beginInboundAddMutationLocked(&InboundRequest{
			MutationID: "generation-new",
			Inbound:    map[string]interface{}{"tag": "same-tag"},
		}, filepath.Join(root, "xray.json"), map[string]interface{}{"tag": "same-tag"})
		if err == nil {
			t.Fatal("reservation unexpectedly persisted into a missing directory")
		}
		assertInboundMutationOwnerInMemory(t, handler, "same-tag", "generation-old")
	})

	t.Run("remove tombstone", func(t *testing.T) {
		handler := loadedInboundMutationFenceTestHandler(missingPath, "same-tag", "generation-old")
		_, _, err := handler.beginInboundMutationLocked("remove", &InboundRequest{
			Tag:        "same-tag",
			MutationID: "generation-old",
		})
		if err == nil {
			t.Fatal("remove tombstone unexpectedly persisted into a missing directory")
		}
		state := handler.inboundMutationFences["same-tag"]
		if _, exists := state.Canceled["generation-old"]; exists {
			t.Fatal("failed tombstone remained in memory")
		}
		assertInboundMutationOwnerInMemory(t, handler, "same-tag", "generation-old")
	})

	t.Run("remove completion", func(t *testing.T) {
		handler := loadedInboundMutationFenceTestHandler(missingPath, "same-tag", "generation-old")
		handler.inboundMutationFences["same-tag"].Canceled["generation-old"] = struct{}{}
		if err := handler.completeInboundMutationRemovalLocked("same-tag", "generation-old"); err == nil {
			t.Fatal("completion unexpectedly persisted into a missing directory")
		}
		assertInboundMutationOwnerInMemory(t, handler, "same-tag", "generation-old")
	})
}

func TestAddReservationRestoresOldOwnerWhenRenameAppliedButDirectorySyncFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	seedInboundMutationOwner(t, handler, "same-tag", "generation-old")

	previousSync := inboundMutationFenceSyncParent
	inboundMutationFenceSyncParent = func(string) error {
		return errors.New("synthetic directory sync failure")
	}
	t.Cleanup(func() { inboundMutationFenceSyncParent = previousSync })

	configPath := inboundMutationFenceTestConfigPath(path)
	previous := readInboundMutationTestConfig(t, configPath, "same-tag")
	_, err := handler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID: "generation-new",
		Inbound:    map[string]interface{}{"tag": "same-tag"},
	}, configPath, previous)
	if err == nil {
		t.Fatal("reservation unexpectedly ignored directory sync failure")
	}
	assertInboundMutationOwnerInMemory(t, handler, "same-tag", "generation-old")

	reloaded := newInboundMutationFenceTestHandler(path)
	if err := reloaded.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatalf("reload mutation fence: %v", err)
	}
	assertInboundMutationOwnerInMemory(t, reloaded, "same-tag", "generation-old")
}

func TestInboundMutationRollbackPersistenceFailureRetainsReservedOwner(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "fence")
	path := filepath.Join(directory, "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
	configPath := filepath.Join(root, "xray.json")
	previous := map[string]interface{}{"tag": "same-tag"}
	writeInboundMutationTestConfig(t, configPath, previous)
	if err := os.Remove(inboundMutationFenceTestConfigPath(path)); err != nil {
		t.Fatalf("remove seed Xray config: %v", err)
	}

	handler.inboundsMu.Lock()
	err := handler.applyInboundAddMutationLocked(&InboundRequest{
		MutationID: "generation-new",
		Inbound:    map[string]interface{}{"tag": "same-tag"},
	}, configPath, previous, func() error {
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := os.Remove(directory); err != nil {
			return err
		}
		if err := os.WriteFile(directory, []byte("not a directory"), 0600); err != nil {
			return err
		}
		return errors.New("synthetic runtime failure")
	})
	handler.inboundsMu.Unlock()
	if err == nil {
		t.Fatal("mutation unexpectedly succeeded")
	}
	// The old state could not be durably restored. Keep the pending WAL in
	// memory rather than publishing either generation as a new committed owner.
	assertInboundMutationOwnerInMemory(t, handler, "same-tag", "generation-old")
	if handler.inboundMutationFences["same-tag"].Pending == nil {
		t.Fatal("failed rollback discarded the pending WAL")
	}
}

func TestInboundMutationRollbackUncertainRecoversFromDurableConfig(t *testing.T) {
	for _, phase := range []string{"grpc", "config", "firewall"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inbound-fences.json")
			handler := newInboundMutationFenceTestHandler(path)
			seedInboundMutationOwner(t, handler, "same-tag", "generation-old")
			handler.inboundMutationRuntimeConverge = func() error { return nil }
			configPath := inboundMutationFenceTestConfigPath(path)
			previous := readInboundMutationTestConfig(t, configPath, "same-tag")
			intended := map[string]interface{}{"tag": "same-tag", "port": float64(2443)}

			handler.inboundsMu.Lock()
			err := handler.applyInboundAddMutationLocked(&InboundRequest{
				MutationID: "generation-new",
				Inbound:    intended,
			}, configPath, previous, func() error {
				writeInboundMutationTestConfig(t, configPath, intended)
				return markInboundMutationRollbackUncertain(errors.New("synthetic " + phase + " rollback failure"))
			})
			handler.inboundsMu.Unlock()
			if err == nil {
				t.Fatalf("%s failure unexpectedly succeeded", phase)
			}

			reloaded := newInboundMutationFenceTestHandler(path)
			if err := reloaded.CompleteInboundMutationRecoveryAfterRuntimeStart(); err != nil {
				t.Fatalf("reload mutation fence: %v", err)
			}
			if got := reloaded.inboundMutationFences["same-tag"].Owner; got != "generation-new" {
				t.Fatalf("owner=%q want conservatively retained generation-new", got)
			}
			if skip, _, err := reloaded.beginInboundMutationLocked("remove", &InboundRequest{
				Tag:        "same-tag",
				MutationID: "generation-old",
			}); err != nil || !skip {
				t.Fatalf("old generation delete must be superseded: skip=%v err=%v", skip, err)
			}
		})
	}
}

func TestInboundMutationInventoryReportsEveryExactOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	handler := newInboundMutationFenceTestHandler(path)
	handler.inboundMutationFencesLoaded = true
	handler.inboundMutationFences = map[string]inboundMutationFenceState{
		"owned":    {Owner: "generation-real", Canceled: make(map[string]struct{})},
		"legacy":   {Canceled: make(map[string]struct{})},
		"sentinel": {Owner: unfencedInboundMutationOwner, Canceled: make(map[string]struct{})},
	}
	inbounds := []map[string]interface{}{
		{"tag": "owned"},
		{"tag": "legacy"},
		{"tag": "sentinel"},
	}
	owners, err := handler.annotateInboundMutationInventoryLocked(inbounds)
	if err != nil {
		t.Fatalf("annotate inventory: %v", err)
	}
	if len(owners) != 2 || owners["owned"] != "generation-real" || owners["sentinel"] != unfencedInboundMutationOwner {
		t.Fatalf("owners=%#v want every non-empty exact owner", owners)
	}
	for _, inbound := range inbounds {
		if known, _ := inbound["_mutation_fence_known"].(bool); !known {
			t.Fatalf("inbound missing fence capability marker: %#v", inbound)
		}
	}
	if got := inbounds[0]["_mutation_id"]; got != "generation-real" {
		t.Fatalf("owned mutation id=%v", got)
	}
	if _, exists := inbounds[1]["_mutation_id"]; exists {
		t.Fatalf("legacy inbound exposed a fake owner: %#v", inbounds[1])
	}
	if got := inbounds[2]["_mutation_id"]; got != unfencedInboundMutationOwner {
		t.Fatalf("sentinel mutation id=%v", got)
	}
}

func TestListInboundsReturnsTopLevelMutationInventory(t *testing.T) {
	handler := newInboundMutationFenceTestHandler(filepath.Join(t.TempDir(), "inbound-fences.json"))
	handler.inboundMutationFencesLoaded = true
	handler.inboundMutationFences["owned"] = inboundMutationFenceState{
		Owner:    "generation-real",
		Canceled: make(map[string]struct{}),
	}
	recorder := httptest.NewRecorder()
	handler.listInbounds(recorder, httptest.NewRequest(http.MethodGet, "/manage/inbounds", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		MutationFenceKnown bool              `json:"mutation_fence_known"`
		MutationOwners     map[string]string `json:"mutation_owners"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if !response.MutationFenceKnown {
		t.Fatal("top-level mutation_fence_known is not true")
	}
	if got := response.MutationOwners["owned"]; got != "generation-real" {
		t.Fatalf("mutation owner=%q", got)
	}
}

func TestInboundMutationFenceMigratesToStableAgentPathBeforeModeSwitch(t *testing.T) {
	root := t.TempDir()
	agentConfigPath := filepath.Join(root, "agent", "config.yaml")
	externalConfigPath := filepath.Join(root, "external-xray", "config.json")
	embeddedConfigPath := filepath.Join(root, "embedded-xray", "config.json")
	externalSidecar := inboundMutationFencePathNextToConfig(externalConfigPath)
	writeInboundMutationFenceFixture(t, externalSidecar, map[string]inboundMutationFenceState{
		"same-tag": {
			Owner: "generation-b",
			Canceled: map[string]struct{}{
				"generation-canceled": {},
			},
		},
	})

	handler := NewManageHandler("token", "", "")
	handler.SetConfigPath(agentConfigPath)
	handler.SetInboundMutationFenceLegacyConfigPaths([]string{externalConfigPath, embeddedConfigPath})
	if err := handler.InitializeInboundMutationFences(); err != nil {
		t.Fatalf("initialize fence migration: %v", err)
	}
	stablePath := filepath.Join(filepath.Dir(agentConfigPath), inboundMutationFenceSidecarName)
	if handler.inboundMutationFencePath != stablePath {
		t.Fatalf("stable path=%q want %q", handler.inboundMutationFencePath, stablePath)
	}
	if _, err := os.Stat(stablePath); err != nil {
		t.Fatalf("stable sidecar: %v", err)
	}
	if _, err := os.Stat(externalSidecar); !os.IsNotExist(err) {
		t.Fatalf("legacy sidecar was not removed: %v", err)
	}

	// Changing Xray mode/path must not change ownership. A stale generation is
	// superseded, while the exact migrated owner remains authorized to remove.
	handler.SetXrayMode("embedded")
	handler.inboundsMu.Lock()
	stale, _, staleErr := handler.beginInboundMutationLocked("remove", &InboundRequest{
		Tag:        "same-tag",
		MutationID: "generation-a",
	})
	exact, _, exactErr := handler.beginInboundMutationLocked("remove", &InboundRequest{
		Tag:        "same-tag",
		MutationID: "generation-b",
	})
	handler.inboundsMu.Unlock()
	if staleErr != nil || !stale {
		t.Fatalf("stale remove after mode switch skip=%v err=%v", stale, staleErr)
	}
	if exactErr != nil || exact {
		t.Fatalf("exact owner remove after mode switch skip=%v err=%v", exact, exactErr)
	}

	reloaded := NewManageHandler("token", "", "")
	reloaded.SetConfigPath(agentConfigPath)
	reloaded.SetInboundMutationFenceLegacyConfigPaths([]string{embeddedConfigPath})
	if err := reloaded.InitializeInboundMutationFences(); err != nil {
		t.Fatalf("reload stable fence: %v", err)
	}
	assertInboundMutationOwnerInMemory(t, reloaded, "same-tag", "generation-b")
}

func TestInboundMutationFenceMigrationFailsClosedOnOwnerConflict(t *testing.T) {
	root := t.TempDir()
	agentConfigPath := filepath.Join(root, "agent", "config.yaml")
	externalConfigPath := filepath.Join(root, "external-xray", "config.json")
	embeddedConfigPath := filepath.Join(root, "embedded-xray", "config.json")
	writeInboundMutationFenceFixture(t, inboundMutationFencePathNextToConfig(externalConfigPath), map[string]inboundMutationFenceState{
		"same-tag": {Owner: "generation-a", Canceled: make(map[string]struct{})},
	})
	writeInboundMutationFenceFixture(t, inboundMutationFencePathNextToConfig(embeddedConfigPath), map[string]inboundMutationFenceState{
		"same-tag": {Owner: "generation-b", Canceled: make(map[string]struct{})},
	})

	handler := NewManageHandler("token", "", "")
	handler.SetConfigPath(agentConfigPath)
	handler.SetInboundMutationFenceLegacyConfigPaths([]string{externalConfigPath, embeddedConfigPath})
	if err := handler.InitializeInboundMutationFences(); err == nil {
		t.Fatal("conflicting legacy owners unexpectedly migrated")
	}
	if handler.inboundMutationFencesLoaded {
		t.Fatal("handler marked conflicting ownership as loaded")
	}
	stablePath := filepath.Join(filepath.Dir(agentConfigPath), inboundMutationFenceSidecarName)
	if _, err := os.Stat(stablePath); !os.IsNotExist(err) {
		t.Fatalf("conflicting migration unexpectedly published stable state: %v", err)
	}
}

func TestInboundMutationFenceReadsVersionOneSidecar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	content := []byte(`{"version":1,"tags":{"same-tag":{"owner":"generation-old","canceled":["generation-canceled"]}}}`)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("write version one sidecar: %v", err)
	}
	handler := newInboundMutationFenceTestHandler(path)
	if err := handler.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatalf("load version one sidecar: %v", err)
	}
	state := handler.inboundMutationFences["same-tag"]
	if state.Owner != "generation-old" {
		t.Fatalf("owner=%q want generation-old", state.Owner)
	}
	if _, ok := state.Canceled["generation-canceled"]; !ok {
		t.Fatal("version one tombstone was not preserved")
	}
}

func TestManageInboundSupersededRemoveResponseIsExplicit(t *testing.T) {
	handler := newInboundMutationFenceTestHandler(filepath.Join(t.TempDir(), "inbound-fences.json"))
	seedInboundMutationOwner(t, handler, "same-tag", "generation-new")
	body := bytes.NewBufferString(`{"action":"remove","tag":"same-tag","mutation_id":"generation-old"}`)
	recorder := httptest.NewRecorder()
	handler.manageInbound(recorder, httptest.NewRequest(http.MethodPost, "/manage/inbounds", body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if superseded, _ := response["superseded"].(bool); !superseded {
		t.Fatalf("response missing superseded=true: %#v", response)
	}
	if changed, ok := response["changed"].(bool); !ok || changed {
		t.Fatalf("response changed=%v want false: %#v", response["changed"], response)
	}
}

func newInboundMutationFenceTestHandler(path string) *ManageHandler {
	return &ManageHandler{
		inboundMutationFencePath: path,
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
		inboundMutationConfigPathResolver: func() string {
			return inboundMutationFenceTestConfigPath(path)
		},
		inboundMutationRuntimeApply: func(
			context.Context,
			string,
			map[string]interface{},
			bool,
		) error {
			return nil
		},
	}
}

func loadedInboundMutationFenceTestHandler(path, tag, owner string) *ManageHandler {
	handler := newInboundMutationFenceTestHandler(path)
	handler.inboundMutationFencesLoaded = true
	handler.inboundMutationFences[tag] = inboundMutationFenceState{
		Owner:    owner,
		Canceled: make(map[string]struct{}),
	}
	return handler
}

func seedInboundMutationOwner(t *testing.T, handler *ManageHandler, tag, mutationID string) {
	t.Helper()
	configPath := inboundMutationFenceTestConfigPath(handler.inboundMutationFencePath)
	intended := map[string]interface{}{"tag": tag}
	previous := readInboundMutationTestConfig(t, configPath, tag)
	handler.inboundsMu.Lock()
	transaction, err := handler.beginInboundAddMutationLocked(&InboundRequest{
		MutationID: mutationID,
		Inbound:    intended,
	}, configPath, previous)
	if err == nil {
		writeInboundMutationTestConfig(t, configPath, intended)
		err = handler.commitInboundMutationLocked(transaction)
	}
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
}

func inboundMutationFenceTestConfigPath(sidecarPath string) string {
	return filepath.Join(filepath.Dir(sidecarPath), "xray-config.json")
}

func writeInboundMutationTestConfig(t *testing.T, configPath string, inbounds ...map[string]interface{}) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		t.Fatalf("create Xray test config directory: %v", err)
	}
	raw := make([]interface{}, 0, len(inbounds))
	for _, inbound := range inbounds {
		raw = append(raw, inbound)
	}
	content, err := json.Marshal(map[string]interface{}{"inbounds": raw})
	if err != nil {
		t.Fatalf("marshal Xray test config: %v", err)
	}
	if err := os.WriteFile(configPath, content, 0644); err != nil {
		t.Fatalf("write Xray test config: %v", err)
	}
}

func readInboundMutationTestConfig(t *testing.T, configPath, tag string) map[string]interface{} {
	t.Helper()
	snapshot, err := captureConfigFile(configPath)
	if err != nil {
		t.Fatalf("snapshot Xray test config: %v", err)
	}
	inbound, err := inboundFromSnapshot(snapshot, tag)
	if err != nil {
		t.Fatalf("read Xray test inbound: %v", err)
	}
	return inbound
}

func assertInboundMutationOwnerRestored(t *testing.T, path, tag, oldMutationID, failedMutationID string) {
	t.Helper()
	reloaded := newInboundMutationFenceTestHandler(path)
	if err := reloaded.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatalf("reload mutation fence: %v", err)
	}
	if got := reloaded.inboundMutationFences[tag].Owner; got != oldMutationID {
		t.Fatalf("owner=%q want restored %q", got, oldMutationID)
	}
	if skip, _, err := reloaded.beginInboundMutationLocked("remove", &InboundRequest{Tag: tag, MutationID: failedMutationID}); err != nil || !skip {
		t.Fatalf("failed generation delete must be superseded: skip=%v err=%v", skip, err)
	}
	if skip, _, err := reloaded.beginInboundMutationLocked("remove", &InboundRequest{Tag: tag, MutationID: oldMutationID}); err != nil || skip {
		t.Fatalf("restored generation delete must remain valid: skip=%v err=%v", skip, err)
	}
}

func assertInboundMutationOwnerInMemory(t *testing.T, handler *ManageHandler, tag, want string) {
	t.Helper()
	if got := handler.inboundMutationFences[tag].Owner; got != want {
		t.Fatalf("owner=%q want %q", got, want)
	}
}

func writeInboundMutationFenceFixture(t *testing.T, path string, states map[string]inboundMutationFenceState) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := writeInboundMutationFenceFileAtomic(path, inboundMutationFenceFileFromStates(states)); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
