package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"mmw-agent/internal/constants"
	"mmw-agent/internal/discovery"
)

const inboundMutationFenceVersion = 2
const inboundMutationFenceSidecarName = ".mmwx-inbound-mutation-fences.json"
const unfencedInboundMutationOwner = "-"
const defaultAgentConfigPath = "/etc/mmw-agent/config.yaml"

var inboundMutationFenceSyncParent = syncInboundMutationFenceParent

type inboundMutationFenceState struct {
	Owner    string
	Canceled map[string]struct{}
	Pending  *inboundMutationFencePending
}

// inboundMutationFencePending is a write-ahead record for an add. Owner stays
// on the last committed generation until the Xray config contains Intended.
// After a crash, the durable config digest lets the Agent commit the new owner,
// restore the prior owner, or fail closed when neither generation matches.
type inboundMutationFencePending struct {
	Owner                string
	ConfigPath           string
	IntendedDigest       string
	PreviousOwner        string
	PreviousStatePresent bool
	PreviousPresent      bool
	PreviousDigest       string
}

type inboundMutationFenceTransaction struct {
	tag            string
	owner          string
	previous       inboundMutationFenceState
	previousExists bool
	active         bool
}

type inboundMutationFenceFile struct {
	Version int                                    `json:"version"`
	Tags    map[string]inboundMutationFenceFileTag `json:"tags"`
}

type inboundMutationFenceFileTag struct {
	Owner    string                           `json:"owner,omitempty"`
	Canceled []string                         `json:"canceled,omitempty"`
	Pending  *inboundMutationFenceFilePending `json:"pending,omitempty"`
}

type inboundMutationFenceFilePending struct {
	Owner                string `json:"owner"`
	ConfigPath           string `json:"config_path"`
	IntendedDigest       string `json:"intended_digest"`
	PreviousOwner        string `json:"previous_owner,omitempty"`
	PreviousStatePresent bool   `json:"previous_state_present"`
	PreviousPresent      bool   `json:"previous_inbound_present"`
	PreviousDigest       string `json:"previous_digest,omitempty"`
}

func (h *ManageHandler) setInboundMutationFenceAgentConfigPath(configPath string) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		configPath = defaultAgentConfigPath
	}
	if absolute, err := filepath.Abs(configPath); err == nil {
		configPath = absolute
	} else {
		configPath = filepath.Clean(configPath)
	}
	h.inboundMutationFencePath = filepath.Join(filepath.Dir(configPath), inboundMutationFenceSidecarName)
	h.inboundMutationFencesLoaded = false
	h.inboundMutationRecoveryReady = false
	h.inboundMutationFences = make(map[string]inboundMutationFenceState)
}

// SetInboundMutationFenceLegacyConfigPaths registers Xray config locations
// known by the loaded Agent configuration. Their adjacent sidecars are merged
// exactly once into the stable Agent-state path during initialization.
func (h *ManageHandler) SetInboundMutationFenceLegacyConfigPaths(configPaths []string) {
	seen := make(map[string]struct{}, len(configPaths))
	legacy := make([]string, 0, len(configPaths))
	for _, configPath := range configPaths {
		if sidecar := inboundMutationFencePathNextToConfig(configPath); sidecar != "" {
			if _, exists := seen[sidecar]; !exists {
				seen[sidecar] = struct{}{}
				legacy = append(legacy, sidecar)
			}
		}
	}
	h.inboundMutationFenceLegacyPaths = legacy
}

// InitializeInboundMutationFences must run before an external Xray config can
// be moved into the embedded location. It migrates every legacy sidecar into a
// stable file next to the Agent config and fails closed on owner conflicts.
func (h *ManageHandler) InitializeInboundMutationFences() error {
	h.inboundsMu.Lock()
	defer h.inboundsMu.Unlock()
	return h.loadInboundMutationFencesLocked()
}

// HasPendingInboundMutationRecovery lets startup avoid all automatic Xray
// config rewrites until a crash-interrupted inbound transaction is converged.
func (h *ManageHandler) HasPendingInboundMutationRecovery() (bool, error) {
	h.inboundsMu.Lock()
	defer h.inboundsMu.Unlock()
	if err := h.loadInboundMutationFencesLocked(); err != nil {
		return false, err
	}
	return hasPendingInboundMutation(h.inboundMutationFences), nil
}

// RecoverInboundMutationFences converges the Xray runtime to its durable config
// before a pending owner can become authoritative. It must run after Xray mode
// selection and startup; callers should retry it after a later successful start.
func (h *ManageHandler) RecoverInboundMutationFences() error {
	h.inboundsMu.Lock()
	defer h.inboundsMu.Unlock()
	if err := h.loadInboundMutationFencesLocked(); err != nil {
		return err
	}
	return h.recoverInboundMutationFencesLocked()
}

func (h *ManageHandler) recoverInboundMutationFencesLocked() error {
	if !hasPendingInboundMutation(h.inboundMutationFences) {
		h.inboundMutationRecoveryReady = true
		return nil
	}
	h.inboundMutationRecoveryReady = false
	if err := h.validatePendingInboundMutationsLocked(); err != nil {
		return err
	}
	restartRuntime := h.inboundMutationRuntimeConverge
	if restartRuntime == nil {
		restartRuntime = h.restartXrayLocked
	}
	if err := restartRuntime(); err != nil {
		return fmt.Errorf("restart Xray runtime for pending inbound mutation: %w", err)
	}
	if err := h.convergePendingInboundRuntimeLocked(); err != nil {
		return fmt.Errorf("converge Xray runtime for pending inbound mutation: %w", err)
	}
	if err := h.reconcileInboundFirewall(); err != nil {
		return fmt.Errorf("converge inbound firewall for pending inbound mutation: %w", err)
	}
	h.inboundMutationRecoveryReady = true
	return h.resolvePendingInboundMutationsLocked()
}

// CompleteInboundMutationRecoveryAfterRuntimeStart is the no-restart variant
// for a caller that has just successfully started Xray from the durable config.
func (h *ManageHandler) CompleteInboundMutationRecoveryAfterRuntimeStart() error {
	h.inboundsMu.Lock()
	defer h.inboundsMu.Unlock()
	return h.completeInboundMutationRecoveryAfterRuntimeStartLocked()
}

func (h *ManageHandler) completeInboundMutationRecoveryAfterRuntimeStartLocked() error {
	if err := h.loadInboundMutationFencesLocked(); err != nil {
		return err
	}
	if !hasPendingInboundMutation(h.inboundMutationFences) {
		h.inboundMutationRecoveryReady = true
		return nil
	}
	h.inboundMutationRecoveryReady = false
	if err := h.validatePendingInboundMutationsLocked(); err != nil {
		return err
	}
	if err := h.convergePendingInboundRuntimeLocked(); err != nil {
		return fmt.Errorf("converge pending inbound after Xray runtime start: %w", err)
	}
	if err := h.reconcileInboundFirewall(); err != nil {
		return fmt.Errorf("converge inbound firewall after Xray runtime start: %w", err)
	}
	h.inboundMutationRecoveryReady = true
	return h.resolvePendingInboundMutationsLocked()
}

func inboundMutationFencePathNextToConfig(configPath string) string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return ""
	}
	if absolute, err := filepath.Abs(configPath); err == nil {
		configPath = absolute
	} else {
		configPath = filepath.Clean(configPath)
	}
	return filepath.Join(filepath.Dir(configPath), inboundMutationFenceSidecarName)
}

// beginInboundMutationLocked records a cancellation before a remove can touch
// Xray. A delayed add with the same mutation ID is then rejected even when the
// remove reached the Agent first. Add ownership is transactional: callers must
// commit it after every runtime and durable side effect succeeds, or roll it
// back on failure. Callers must hold inboundsMu.
func (h *ManageHandler) beginInboundMutationLocked(action string, req *InboundRequest) (bool, *inboundMutationFenceTransaction, error) {
	mutationID := strings.TrimSpace(req.MutationID)
	switch action {
	case "add":
		configPath := h.findXrayConfigPath()
		var previousInbound map[string]interface{}
		if configPath != "" && req.Inbound != nil {
			tag, _ := req.Inbound["tag"].(string)
			snapshot, err := captureConfigFile(configPath)
			if err != nil {
				return false, nil, fmt.Errorf("snapshot Xray config for inbound mutation: %w", err)
			}
			previousInbound, err = inboundFromSnapshot(snapshot, strings.TrimSpace(tag))
			if err != nil {
				return false, nil, err
			}
		}
		transaction, err := h.beginInboundAddMutationLocked(req, configPath, previousInbound)
		return false, transaction, err

	case "remove":
		req.Tag = strings.TrimSpace(req.Tag)
		if req.Tag == "" {
			return false, nil, nil
		}
		if err := h.ensureInboundMutationFencesLocked(); err != nil {
			return false, nil, err
		}
		previous := h.inboundMutationFences[req.Tag]
		previous = cloneInboundMutationFenceState(previous)
		state := cloneInboundMutationFenceState(previous)
		if state.Canceled == nil {
			state.Canceled = make(map[string]struct{})
		}
		if mutationID == "" {
			if state.Owner != "" {
				return false, nil, fmt.Errorf("mutation_id is required to remove owned inbound %s", req.Tag)
			}
			return false, nil, nil
		}
		state.Canceled[mutationID] = struct{}{}
		candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
		candidate[req.Tag] = state
		if err := h.persistInboundMutationFenceStatesLocked(candidate); err != nil {
			if inboundMutationFenceWriteApplied(err) {
				h.inboundMutationFences = candidate
			}
			return false, nil, err
		}
		h.inboundMutationFences = candidate
		return state.Owner != "" && state.Owner != mutationID, nil, nil
	}
	return false, nil, nil
}

// beginInboundAddMutationLocked writes a pending WAL entry while keeping Owner
// on the last committed generation. configPath and previousInbound must come
// from the same snapshot that the caller will use for rollback.
func (h *ManageHandler) beginInboundAddMutationLocked(
	req *InboundRequest,
	configPath string,
	previousInbound map[string]interface{},
) (*inboundMutationFenceTransaction, error) {
	if req.Inbound == nil {
		return nil, nil
	}
	tag, _ := req.Inbound["tag"].(string)
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil, nil
	}
	if err := h.ensureInboundMutationFencesLocked(); err != nil {
		return nil, err
	}

	mutationID := strings.TrimSpace(req.MutationID)
	previous, previousExists := h.inboundMutationFences[tag]
	previous = cloneInboundMutationFenceState(previous)
	if previous.Pending != nil {
		return nil, fmt.Errorf("inbound mutation recovery is still pending for %s", tag)
	}
	if mutationID == "" {
		if previous.Owner != "" || len(previous.Canceled) > 0 {
			// Once a tag has generation history, accepting another unfenced add
			// would create an inbound that no request can safely identify.
			return nil, fmt.Errorf("mutation_id is required to replace fenced inbound %s", tag)
		}
		return nil, nil
	}
	if _, canceled := previous.Canceled[mutationID]; canceled {
		return nil, fmt.Errorf("inbound mutation %s for %s was canceled", mutationID, tag)
	}

	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil, fmt.Errorf("Xray config path is required to fence inbound %s", tag)
	}
	if absolute, err := filepath.Abs(configPath); err == nil {
		configPath = absolute
	} else {
		configPath = filepath.Clean(configPath)
	}
	intendedDigest, err := canonicalInboundMutationDigest(req.Inbound)
	if err != nil {
		return nil, fmt.Errorf("digest intended inbound %s: %w", tag, err)
	}
	previousDigest, err := canonicalInboundMutationDigest(previousInbound)
	if err != nil {
		return nil, fmt.Errorf("digest previous inbound %s: %w", tag, err)
	}

	state := cloneInboundMutationFenceState(previous)
	if state.Canceled == nil {
		state.Canceled = make(map[string]struct{})
	}
	state.Pending = &inboundMutationFencePending{
		Owner:                mutationID,
		ConfigPath:           configPath,
		IntendedDigest:       intendedDigest,
		PreviousOwner:        previous.Owner,
		PreviousStatePresent: previousExists,
		PreviousPresent:      previousInbound != nil,
		PreviousDigest:       previousDigest,
	}
	candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
	candidate[tag] = state
	if err := h.persistInboundMutationFenceStatesLocked(candidate); err != nil {
		if inboundMutationFenceWriteApplied(err) {
			h.inboundMutationFences = candidate
			rollbackCandidate := cloneInboundMutationFenceStates(candidate)
			if previousExists {
				rollbackCandidate[tag] = cloneInboundMutationFenceState(previous)
			} else {
				delete(rollbackCandidate, tag)
			}
			rollbackErr := h.persistInboundMutationFenceStatesLocked(rollbackCandidate)
			if rollbackErr == nil || inboundMutationFenceWriteApplied(rollbackErr) {
				h.inboundMutationFences = rollbackCandidate
			}
			if rollbackErr != nil {
				return nil, errors.Join(err, fmt.Errorf("restore inbound mutation fence after reservation failure: %w", rollbackErr))
			}
		}
		return nil, err
	}
	h.inboundMutationFences = candidate
	return &inboundMutationFenceTransaction{
		tag:            tag,
		owner:          mutationID,
		previous:       previous,
		previousExists: previousExists,
		active:         true,
	}, nil
}

type inboundMutationReservationError struct {
	err error
}

func (err *inboundMutationReservationError) Error() string {
	return fmt.Sprintf("Failed to reserve inbound mutation: %v", err.err)
}

func (err *inboundMutationReservationError) Unwrap() error {
	return err.err
}

// applyInboundAddMutationLocked keeps the pending WAL active for the entire
// config/runtime/firewall transaction. A confirmed rollback restores the prior
// state; an uncertain rollback deliberately leaves pending for digest recovery.
func (h *ManageHandler) applyInboundAddMutationLocked(
	req *InboundRequest,
	configPath string,
	previousInbound map[string]interface{},
	apply func() error,
) (returnErr error) {
	transaction, err := h.beginInboundAddMutationLocked(req, configPath, previousInbound)
	if err != nil {
		return &inboundMutationReservationError{err: err}
	}
	defer func() {
		if transaction == nil || !transaction.active {
			return
		}
		if rollbackErr := h.rollbackInboundMutationLocked(transaction); rollbackErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("failed to restore inbound mutation ownership: %w", rollbackErr))
		}
	}()

	if err := apply(); err != nil {
		var uncertain *inboundMutationRollbackUncertainError
		if errors.As(err, &uncertain) {
			// The durable config decides the owner on the next recovery pass. Do
			// not publish either generation while the actual result is uncertain.
			transaction.abandonForRecovery()
			h.inboundMutationRecoveryReady = false
			if recoveryErr := h.recoverInboundMutationFencesLocked(); recoveryErr != nil {
				return errors.Join(err, fmt.Errorf("recover uncertain inbound mutation: %w", recoveryErr))
			}
		}
		return err
	}
	if err := h.commitInboundMutationLocked(transaction); err != nil {
		return fmt.Errorf("commit inbound mutation ownership: %w", err)
	}
	return nil
}

func (transaction *inboundMutationFenceTransaction) abandonForRecovery() {
	if transaction != nil {
		transaction.active = false
	}
}

func (h *ManageHandler) commitInboundMutationLocked(transaction *inboundMutationFenceTransaction) error {
	if transaction == nil || !transaction.active {
		return nil
	}
	state, exists := h.inboundMutationFences[transaction.tag]
	if !exists || state.Pending == nil || state.Pending.Owner != transaction.owner {
		transaction.active = false
		return fmt.Errorf("pending inbound mutation %s for %s was lost", transaction.owner, transaction.tag)
	}
	actualDigest, actualPresent, err := inboundMutationDigestFromConfig(state.Pending.ConfigPath, transaction.tag)
	if err != nil || !actualPresent || actualDigest != state.Pending.IntendedDigest {
		transaction.active = false
		if err != nil {
			return fmt.Errorf("verify durable inbound config for %s: %w", transaction.tag, err)
		}
		return fmt.Errorf("durable inbound config for %s does not match the pending generation", transaction.tag)
	}
	candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
	candidateState := cloneInboundMutationFenceState(state)
	candidateState.Owner = transaction.owner
	candidateState.Pending = nil
	candidate[transaction.tag] = candidateState
	err = h.persistInboundMutationFenceStatesLocked(candidate)
	if err == nil || inboundMutationFenceWriteApplied(err) {
		h.inboundMutationFences = candidate
	}
	// The config already contains the intended generation. On any persistence
	// failure, keep either durable pending or the applied commit for recovery;
	// never let the deferred rollback claim the previous owner again.
	transaction.active = false
	return err
}

func (h *ManageHandler) rollbackInboundMutationLocked(transaction *inboundMutationFenceTransaction) error {
	if transaction == nil || !transaction.active {
		return nil
	}
	candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
	if transaction.previousExists {
		candidate[transaction.tag] = cloneInboundMutationFenceState(transaction.previous)
	} else {
		delete(candidate, transaction.tag)
	}
	err := h.persistInboundMutationFenceStatesLocked(candidate)
	if err == nil || inboundMutationFenceWriteApplied(err) {
		h.inboundMutationFences = candidate
	}
	transaction.active = false
	if err != nil {
		return fmt.Errorf("restore inbound mutation fence for %s: %w", transaction.tag, err)
	}
	return nil
}

func cloneInboundMutationFenceState(state inboundMutationFenceState) inboundMutationFenceState {
	cloned := inboundMutationFenceState{Owner: state.Owner}
	if state.Canceled != nil {
		cloned.Canceled = make(map[string]struct{}, len(state.Canceled))
		for mutationID := range state.Canceled {
			cloned.Canceled[mutationID] = struct{}{}
		}
	}
	if state.Pending != nil {
		pending := *state.Pending
		cloned.Pending = &pending
	}
	return cloned
}

func cloneInboundMutationFenceStates(states map[string]inboundMutationFenceState) map[string]inboundMutationFenceState {
	cloned := make(map[string]inboundMutationFenceState, len(states))
	for tag, state := range states {
		cloned[tag] = cloneInboundMutationFenceState(state)
	}
	return cloned
}

// annotateInboundMutationInventoryLocked exposes every non-empty exact owner.
// The historical "-" sentinel is included: the control plane must echo that
// exact value to remove the resource, while an empty legacy remove stays
// rejected. Callers must hold inboundsMu.
func (h *ManageHandler) annotateInboundMutationInventoryLocked(inbounds []map[string]interface{}) (map[string]string, error) {
	if err := h.ensureInboundMutationFencesLocked(); err != nil {
		return nil, err
	}
	owners := make(map[string]string)
	for tag, state := range h.inboundMutationFences {
		owner := strings.TrimSpace(state.Owner)
		if owner != "" {
			owners[tag] = owner
		}
	}
	for _, inbound := range inbounds {
		inbound["_mutation_fence_known"] = true
		tag, _ := inbound["tag"].(string)
		if owner, ok := owners[strings.TrimSpace(tag)]; ok {
			inbound["_mutation_id"] = owner
		}
	}
	return owners, nil
}

type inboundMutationRollbackUncertainError struct {
	err error
}

func (err *inboundMutationRollbackUncertainError) Error() string {
	return err.err.Error()
}

func (err *inboundMutationRollbackUncertainError) Unwrap() error {
	return err.err
}

func markInboundMutationRollbackUncertain(err error) error {
	if err == nil {
		return nil
	}
	return &inboundMutationRollbackUncertainError{err: err}
}

func (h *ManageHandler) completeInboundMutationRemovalLocked(tag, mutationID string) error {
	tag = strings.TrimSpace(tag)
	mutationID = strings.TrimSpace(mutationID)
	if tag == "" || !h.inboundMutationFencesLoaded {
		return nil
	}
	state, ok := h.inboundMutationFences[tag]
	if !ok {
		return nil
	}
	if mutationID == "" || state.Owner == mutationID {
		if state.Owner == "" {
			return nil
		}
		candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
		candidateState := cloneInboundMutationFenceState(state)
		candidateState.Owner = ""
		candidate[tag] = candidateState
		if err := h.persistInboundMutationFenceStatesLocked(candidate); err != nil {
			if inboundMutationFenceWriteApplied(err) {
				h.inboundMutationFences = candidate
			}
			return err
		}
		h.inboundMutationFences = candidate
	}
	return nil
}

func (h *ManageHandler) ensureInboundMutationFencesLocked() error {
	if err := h.loadInboundMutationFencesLocked(); err != nil {
		return err
	}
	if hasPendingInboundMutation(h.inboundMutationFences) && !h.inboundMutationRecoveryReady {
		return fmt.Errorf("inbound mutation ownership is waiting for Xray runtime convergence")
	}
	if h.inboundMutationRecoveryReady {
		return h.resolvePendingInboundMutationsLocked()
	}
	return nil
}

func (h *ManageHandler) loadInboundMutationFencesLocked() error {
	path := h.inboundMutationFencePath
	if path == "" {
		h.setInboundMutationFenceAgentConfigPath("")
		path = h.inboundMutationFencePath
	}
	if h.inboundMutationFencesLoaded && h.inboundMutationFencePath == path {
		return nil
	}

	states, _, err := readInboundMutationFenceStates(path)
	if err != nil {
		return err
	}
	origins := make(map[string]string, len(states))
	for tag := range states {
		origins[tag] = path
	}

	legacyFiles := make([]string, 0)
	for _, legacyPath := range h.inboundMutationFenceMigrationPathsLocked() {
		if legacyPath == path {
			continue
		}
		legacyStates, exists, err := readInboundMutationFenceStates(legacyPath)
		if err != nil {
			return err
		}
		if !exists {
			continue
		}
		if err := mergeInboundMutationFenceStates(states, origins, legacyStates, legacyPath); err != nil {
			return err
		}
		legacyFiles = append(legacyFiles, legacyPath)
	}

	if len(legacyFiles) > 0 {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return fmt.Errorf("create inbound mutation fence directory: %w", err)
		}
		if err := writeInboundMutationFenceFileAtomic(path, inboundMutationFenceFileFromStates(states)); err != nil {
			return fmt.Errorf("migrate inbound mutation fence: %w", err)
		}
		for _, legacyPath := range legacyFiles {
			if err := os.Remove(legacyPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove migrated inbound mutation fence %s: %w", legacyPath, err)
			}
			if err := inboundMutationFenceSyncParent(legacyPath); err != nil {
				return fmt.Errorf("sync migrated inbound mutation fence directory %s: %w", filepath.Dir(legacyPath), err)
			}
		}
	}
	h.inboundMutationFencePath = path
	h.inboundMutationFences = states
	h.inboundMutationFencesLoaded = true
	return nil
}

func hasPendingInboundMutation(states map[string]inboundMutationFenceState) bool {
	for _, state := range states {
		if state.Pending != nil {
			return true
		}
	}
	return false
}

func (h *ManageHandler) resolvePendingInboundMutationsLocked() error {
	candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
	changed := false
	tags := make([]string, 0, len(candidate))
	for tag, state := range candidate {
		if state.Pending != nil {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	for _, tag := range tags {
		state := candidate[tag]
		pending := state.Pending
		if pending == nil {
			continue
		}
		if pending.PreviousOwner != state.Owner {
			return fmt.Errorf("inbound mutation WAL owner mismatch for tag %q", tag)
		}
		resolution, err := h.pendingInboundMutationResolution(tag, pending)
		if err != nil {
			return fmt.Errorf("recover pending inbound mutation for %s: %w", tag, err)
		}
		switch resolution {
		case pendingInboundMutationIntended:
			state.Owner = pending.Owner
			state.Pending = nil
			candidate[tag] = state
			changed = true
		case pendingInboundMutationPrevious:
			state.Owner = pending.PreviousOwner
			state.Pending = nil
			if !pending.PreviousStatePresent && state.Owner == "" && len(state.Canceled) == 0 {
				delete(candidate, tag)
			} else {
				candidate[tag] = state
			}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := h.persistInboundMutationFenceStatesLocked(candidate); err != nil {
		if inboundMutationFenceWriteApplied(err) {
			h.inboundMutationFences = candidate
		}
		return fmt.Errorf("persist recovered inbound mutation ownership: %w", err)
	}
	h.inboundMutationFences = candidate
	return nil
}

type pendingInboundMutationResolution uint8

const (
	pendingInboundMutationPrevious pendingInboundMutationResolution = iota + 1
	pendingInboundMutationIntended
)

func (h *ManageHandler) validatePendingInboundMutationsLocked() error {
	for tag, state := range h.inboundMutationFences {
		if state.Pending == nil {
			continue
		}
		if state.Pending.PreviousOwner != state.Owner {
			return fmt.Errorf("inbound mutation WAL owner mismatch for tag %q", tag)
		}
		if _, err := h.pendingInboundMutationResolution(tag, state.Pending); err != nil {
			return fmt.Errorf("validate pending inbound mutation for %s: %w", tag, err)
		}
	}
	return nil
}

func (h *ManageHandler) pendingInboundMutationResolution(
	tag string,
	pending *inboundMutationFencePending,
) (pendingInboundMutationResolution, error) {
	actualDigest, actualPresent, err := h.pendingInboundMutationActualDigest(tag, pending)
	if err != nil {
		return 0, err
	}
	if actualPresent && actualDigest == pending.IntendedDigest {
		return pendingInboundMutationIntended, nil
	}
	if actualPresent == pending.PreviousPresent && (!actualPresent || actualDigest == pending.PreviousDigest) {
		return pendingInboundMutationPrevious, nil
	}
	return 0, fmt.Errorf("durable config does not match intended or previous generation")
}

func (h *ManageHandler) pendingInboundMutationActualDigest(
	tag string,
	pending *inboundMutationFencePending,
) (string, bool, error) {
	_, digest, present, err := h.pendingInboundMutationActualInbound(tag, pending)
	return digest, present, err
}

func (h *ManageHandler) pendingInboundMutationActualInbound(
	tag string,
	pending *inboundMutationFencePending,
) (map[string]interface{}, string, bool, error) {
	paths := make([]string, 0, 2)
	seen := make(map[string]struct{}, 2)
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if absolute, err := filepath.Abs(path); err == nil {
			path = absolute
		}
		if _, exists := seen[path]; exists {
			return
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	add(pending.ConfigPath)
	add(h.findXrayConfigPath())

	foundConfig := false
	var actualInbound map[string]interface{}
	var actualDigest string
	var actualPresent bool
	for _, path := range paths {
		snapshot, err := captureConfigFile(path)
		if err != nil {
			return nil, "", false, err
		}
		if !snapshot.existed {
			continue
		}
		inbound, present, err := inboundMutationFromSnapshot(snapshot, path, tag)
		if err != nil {
			return nil, "", false, err
		}
		digest, err := canonicalInboundMutationDigest(inbound)
		if err != nil {
			return nil, "", false, err
		}
		if !foundConfig {
			foundConfig = true
			actualInbound = inbound
			actualDigest = digest
			actualPresent = present
			continue
		}
		if actualPresent != present || actualDigest != digest {
			return nil, "", false, fmt.Errorf("Xray config paths disagree about inbound %q", tag)
		}
	}
	if !foundConfig {
		return nil, "", false, fmt.Errorf("no durable Xray config is available for pending mutation")
	}
	return actualInbound, actualDigest, actualPresent, nil
}

func (h *ManageHandler) convergePendingInboundRuntimeLocked() error {
	tags := make([]string, 0, len(h.inboundMutationFences))
	for tag, state := range h.inboundMutationFences {
		if state.Pending != nil {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	for _, tag := range tags {
		state := h.inboundMutationFences[tag]
		inbound, _, present, err := h.pendingInboundMutationActualInbound(tag, state.Pending)
		if err != nil {
			return fmt.Errorf("read durable inbound %s for runtime convergence: %w", tag, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if h.inboundMutationRuntimeApply != nil {
			err = h.inboundMutationRuntimeApply(ctx, tag, inbound, present)
		} else if present {
			err = h.replaceRuntimeInbound(ctx, tag, inbound)
		} else {
			err = h.removeRuntimeInboundForRecovery(ctx, tag)
		}
		cancel()
		if err != nil {
			return fmt.Errorf("apply durable inbound %s to runtime: %w", tag, err)
		}
	}
	return nil
}

func inboundMutationDigestFromConfig(configPath, tag string) (string, bool, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return "", false, fmt.Errorf("pending mutation has no Xray config path")
	}
	snapshot, err := captureConfigFile(configPath)
	if err != nil {
		return "", false, err
	}
	if !snapshot.existed {
		return "", false, nil
	}
	return inboundMutationDigestFromSnapshot(snapshot, configPath, tag)
}

func inboundMutationDigestFromSnapshot(snapshot configFileSnapshot, configPath, tag string) (string, bool, error) {
	inbound, present, err := inboundMutationFromSnapshot(snapshot, configPath, tag)
	if err != nil || !present {
		return "", present, err
	}
	digest, err := canonicalInboundMutationDigest(inbound)
	return digest, true, err
}

func inboundMutationFromSnapshot(snapshot configFileSnapshot, configPath, tag string) (map[string]interface{}, bool, error) {
	var config map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(string(snapshot.content)))
	decoder.UseNumber()
	if err := decoder.Decode(&config); err != nil {
		return nil, false, fmt.Errorf("parse Xray config %s: %w", configPath, err)
	}
	rawInbounds, _ := config["inbounds"].([]interface{})
	var found map[string]interface{}
	for _, raw := range rawInbounds {
		inbound, _ := raw.(map[string]interface{})
		inboundTag, _ := inbound["tag"].(string)
		if strings.TrimSpace(inboundTag) != tag {
			continue
		}
		if found != nil {
			return nil, false, fmt.Errorf("Xray config %s contains duplicate inbound tag %q", configPath, tag)
		}
		found = inbound
	}
	if found == nil {
		return nil, false, nil
	}
	return found, true, nil
}

func canonicalInboundMutationDigest(inbound map[string]interface{}) (string, error) {
	if inbound == nil {
		return "", nil
	}
	content, err := json.Marshal(inbound)
	if err != nil {
		return "", err
	}
	var canonical interface{}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.UseNumber()
	if err := decoder.Decode(&canonical); err != nil {
		return "", err
	}
	content, err = json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return fmt.Sprintf("%x", digest[:]), nil
}

func (h *ManageHandler) inboundMutationFenceMigrationPathsLocked() []string {
	seen := map[string]struct{}{h.inboundMutationFencePath: {}}
	paths := make([]string, 0, len(h.inboundMutationFenceLegacyPaths)+len(constants.DefaultXrayConfigPaths)+1)
	add := func(configPath string) {
		sidecar := inboundMutationFencePathNextToConfig(configPath)
		if sidecar == "" {
			return
		}
		if _, exists := seen[sidecar]; exists {
			return
		}
		seen[sidecar] = struct{}{}
		paths = append(paths, sidecar)
	}
	for _, sidecar := range h.inboundMutationFenceLegacyPaths {
		if absolute, err := filepath.Abs(sidecar); err == nil {
			sidecar = absolute
		}
		if sidecar == "" {
			continue
		}
		if _, exists := seen[sidecar]; !exists {
			seen[sidecar] = struct{}{}
			paths = append(paths, sidecar)
		}
	}
	if discovered := discovery.Discover(); discovered.ConfigPath != "" {
		add(discovered.ConfigPath)
	}
	for _, configPath := range constants.DefaultXrayConfigPaths {
		add(configPath)
	}
	return paths
}

func readInboundMutationFenceStates(path string) (map[string]inboundMutationFenceState, bool, error) {
	states := make(map[string]inboundMutationFenceState)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return states, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect inbound mutation fence %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("inbound mutation fence %s is not a regular file", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read inbound mutation fence %s: %w", path, err)
	}
	var file inboundMutationFenceFile
	if err := json.Unmarshal(content, &file); err != nil {
		return nil, false, fmt.Errorf("parse inbound mutation fence %s: %w", path, err)
	}
	if file.Version != 1 && file.Version != inboundMutationFenceVersion {
		return nil, false, fmt.Errorf("unsupported inbound mutation fence version %d in %s", file.Version, path)
	}
	origins := make(map[string]string)
	for rawTag, entry := range file.Tags {
		tag := strings.TrimSpace(rawTag)
		if tag == "" {
			continue
		}
		state := inboundMutationFenceState{
			Owner:    strings.TrimSpace(entry.Owner),
			Canceled: make(map[string]struct{}, len(entry.Canceled)),
		}
		for _, mutationID := range entry.Canceled {
			if mutationID = strings.TrimSpace(mutationID); mutationID != "" {
				state.Canceled[mutationID] = struct{}{}
			}
		}
		if entry.Pending != nil {
			pending := &inboundMutationFencePending{
				Owner:                strings.TrimSpace(entry.Pending.Owner),
				ConfigPath:           strings.TrimSpace(entry.Pending.ConfigPath),
				IntendedDigest:       strings.TrimSpace(entry.Pending.IntendedDigest),
				PreviousOwner:        strings.TrimSpace(entry.Pending.PreviousOwner),
				PreviousStatePresent: entry.Pending.PreviousStatePresent,
				PreviousPresent:      entry.Pending.PreviousPresent,
				PreviousDigest:       strings.TrimSpace(entry.Pending.PreviousDigest),
			}
			if pending.Owner == "" || pending.ConfigPath == "" || pending.IntendedDigest == "" {
				return nil, false, fmt.Errorf("invalid pending inbound mutation for tag %q in %s", tag, path)
			}
			if pending.PreviousPresent && pending.PreviousDigest == "" {
				return nil, false, fmt.Errorf("pending inbound mutation for tag %q has no previous digest in %s", tag, path)
			}
			if pending.PreviousOwner != state.Owner {
				return nil, false, fmt.Errorf("pending inbound mutation owner mismatch for tag %q in %s", tag, path)
			}
			state.Pending = pending
		}
		if state.Owner == "" && len(state.Canceled) == 0 && state.Pending == nil {
			continue
		}
		if err := mergeInboundMutationFenceStates(states, origins, map[string]inboundMutationFenceState{tag: state}, path); err != nil {
			return nil, false, err
		}
	}
	return states, true, nil
}

func mergeInboundMutationFenceStates(
	destination map[string]inboundMutationFenceState,
	origins map[string]string,
	source map[string]inboundMutationFenceState,
	sourcePath string,
) error {
	for tag, incoming := range source {
		existing, exists := destination[tag]
		if !exists {
			destination[tag] = cloneInboundMutationFenceState(incoming)
			origins[tag] = sourcePath
			continue
		}
		if strings.TrimSpace(existing.Owner) != strings.TrimSpace(incoming.Owner) {
			return fmt.Errorf("inbound mutation owner conflict for tag %q between %s and %s", tag, origins[tag], sourcePath)
		}
		if !equalInboundMutationFencePending(existing.Pending, incoming.Pending) {
			return fmt.Errorf("pending inbound mutation conflict for tag %q between %s and %s", tag, origins[tag], sourcePath)
		}
		if existing.Canceled == nil {
			existing.Canceled = make(map[string]struct{})
		}
		for mutationID := range incoming.Canceled {
			existing.Canceled[mutationID] = struct{}{}
		}
		destination[tag] = existing
	}
	return nil
}

func equalInboundMutationFencePending(left, right *inboundMutationFencePending) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func (h *ManageHandler) persistInboundMutationFenceStatesLocked(states map[string]inboundMutationFenceState) error {
	if !h.inboundMutationFencesLoaded || h.inboundMutationFencePath == "" {
		return fmt.Errorf("inbound mutation fence is not loaded")
	}
	if err := os.MkdirAll(filepath.Dir(h.inboundMutationFencePath), 0700); err != nil {
		return fmt.Errorf("create inbound mutation fence directory: %w", err)
	}
	return writeInboundMutationFenceFileAtomic(h.inboundMutationFencePath, inboundMutationFenceFileFromStates(states))
}

func inboundMutationFenceFileFromStates(states map[string]inboundMutationFenceState) inboundMutationFenceFile {
	file := inboundMutationFenceFile{Version: inboundMutationFenceVersion, Tags: make(map[string]inboundMutationFenceFileTag, len(states))}
	for tag, state := range states {
		entry := inboundMutationFenceFileTag{Owner: state.Owner}
		for mutationID := range state.Canceled {
			entry.Canceled = append(entry.Canceled, mutationID)
		}
		sort.Strings(entry.Canceled)
		if state.Pending != nil {
			entry.Pending = &inboundMutationFenceFilePending{
				Owner:                state.Pending.Owner,
				ConfigPath:           state.Pending.ConfigPath,
				IntendedDigest:       state.Pending.IntendedDigest,
				PreviousOwner:        state.Pending.PreviousOwner,
				PreviousStatePresent: state.Pending.PreviousStatePresent,
				PreviousPresent:      state.Pending.PreviousPresent,
				PreviousDigest:       state.Pending.PreviousDigest,
			}
		}
		if entry.Owner != "" || len(entry.Canceled) > 0 || entry.Pending != nil {
			file.Tags[tag] = entry
		}
	}
	return file
}

type inboundMutationFenceDurabilityError struct {
	err error
}

func (err *inboundMutationFenceDurabilityError) Error() string {
	return fmt.Sprintf("inbound mutation fence was renamed but parent directory sync failed: %v", err.err)
}

func (err *inboundMutationFenceDurabilityError) Unwrap() error {
	return err.err
}

func inboundMutationFenceWriteApplied(err error) bool {
	var durabilityErr *inboundMutationFenceDurabilityError
	return errors.As(err, &durabilityErr)
}

func writeInboundMutationFenceFileAtomic(path string, value any) (returnErr error) {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mmwx-inbound-fence-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() { _ = os.Remove(tmpPath) }()
	defer func() {
		if !closed {
			if closeErr := tmp.Close(); returnErr == nil && closeErr != nil {
				returnErr = closeErr
			}
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err := inboundMutationFenceSyncParent(path); err != nil {
		return &inboundMutationFenceDurabilityError{err: err}
	}
	return nil
}
