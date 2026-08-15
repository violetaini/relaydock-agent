package limiter

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	persistentSnapshotVersion = 1
	persistentMarkerVersion   = 1
)

// PersistentInboundSnapshot is the minimum limiter state that must exist
// before a durable WireGuard peer is allowed to accept traffic after restart.
type PersistentInboundSnapshot struct {
	InboundTag     string              `json:"inbound_tag"`
	NodeLimit      uint64              `json:"node_limit,omitempty"`
	Users          []UserInfo          `json:"users"`
	WireGuardPeers []WireGuardPeerUser `json:"wireguard_peers"`
}

type persistentSnapshotFile struct {
	Version  int                         `json:"version"`
	Inbounds []PersistentInboundSnapshot `json:"inbounds"`
}

type persistentRequiredMarker struct {
	Version int `json:"version"`
}

var persistentSnapshots struct {
	sync.Mutex
	path       string
	markerPath string
}

// ConfigurePersistentSnapshotPath sets the process-wide state file used by
// both limiter delivery paths and embedded Xray startup.
func ConfigurePersistentSnapshotPath(path string) {
	persistentSnapshots.Lock()
	persistentSnapshots.path = strings.TrimSpace(path)
	if persistentSnapshots.path == "" {
		persistentSnapshots.markerPath = ""
	} else {
		persistentSnapshots.markerPath = persistentSnapshots.path + ".required"
	}
	persistentSnapshots.Unlock()
}

func canonicalPersistentWireGuardHostIP(value string) (string, bool) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || !prefix.IsValid() || prefix.Bits() != prefix.Addr().BitLen() {
		return "", false
	}
	return prefix.Addr().Unmap().String(), true
}

func validatePersistentInboundSnapshot(snapshot PersistentInboundSnapshot) error {
	if snapshot.InboundTag == "" || snapshot.InboundTag != strings.TrimSpace(snapshot.InboundTag) {
		return errors.New("limiter snapshot inbound_tag is required")
	}
	users := make(map[string]struct{}, len(snapshot.Users))
	for _, user := range snapshot.Users {
		email := strings.TrimSpace(user.Email)
		if email == "" || email != user.Email {
			return fmt.Errorf("limiter snapshot %s has an empty user email", snapshot.InboundTag)
		}
		users[email] = struct{}{}
	}
	addresses := make(map[string]string, len(snapshot.WireGuardPeers))
	for _, peer := range snapshot.WireGuardPeers {
		email := strings.TrimSpace(peer.Email)
		if email == "" || email != peer.Email {
			return fmt.Errorf("limiter snapshot %s WireGuard peer %q has an invalid email", snapshot.InboundTag, peer.Address)
		}
		if _, ok := users[email]; !ok {
			return fmt.Errorf("limiter snapshot %s WireGuard peer %q has no matching user policy", snapshot.InboundTag, peer.Address)
		}
		address, ok := canonicalPersistentWireGuardHostIP(peer.Address)
		if !ok || address == "" || peer.Address != strings.TrimSpace(peer.Address) {
			return fmt.Errorf("limiter snapshot %s has invalid WireGuard address %q", snapshot.InboundTag, peer.Address)
		}
		if owner, exists := addresses[address]; exists && owner != email {
			return fmt.Errorf("limiter snapshot %s WireGuard address %s has multiple owners", snapshot.InboundTag, address)
		}
		addresses[address] = email
	}
	return nil
}

func readPersistentSnapshots(path string) ([]PersistentInboundSnapshot, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var state persistentSnapshotFile
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, true, fmt.Errorf("decode limiter snapshot: %w", err)
	}
	if state.Version != persistentSnapshotVersion {
		return nil, true, fmt.Errorf("unsupported limiter snapshot version %d", state.Version)
	}
	seen := make(map[string]struct{}, len(state.Inbounds))
	for _, snapshot := range state.Inbounds {
		if err := validatePersistentInboundSnapshot(snapshot); err != nil {
			return nil, true, err
		}
		tag := strings.TrimSpace(snapshot.InboundTag)
		if _, duplicate := seen[tag]; duplicate {
			return nil, true, fmt.Errorf("limiter snapshot contains duplicate inbound %s", tag)
		}
		seen[tag] = struct{}{}
	}
	return state.Inbounds, true, nil
}

func readPersistentRequiredMarker(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var marker persistentRequiredMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return true, fmt.Errorf("decode limiter required marker: %w", err)
	}
	if marker.Version != persistentMarkerVersion {
		return true, fmt.Errorf("unsupported limiter required marker version %d", marker.Version)
	}
	return true, nil
}

// LoadPersistentInboundSnapshots returns the last acknowledged limiter state.
// Corrupt state is an error so embedded Xray cannot start durable peers without
// their identity and policy mapping.
func LoadPersistentInboundSnapshots() ([]PersistentInboundSnapshot, error) {
	persistentSnapshots.Lock()
	defer persistentSnapshots.Unlock()
	return loadPersistentInboundSnapshotsLocked()
}

func loadPersistentInboundSnapshotsLocked() ([]PersistentInboundSnapshot, error) {
	if persistentSnapshots.path == "" {
		return nil, nil
	}
	required, err := readPersistentRequiredMarker(persistentSnapshots.markerPath)
	if err != nil {
		return nil, err
	}
	snapshots, exists, err := readPersistentSnapshots(persistentSnapshots.path)
	if err != nil {
		return nil, err
	}
	if required && !exists {
		return nil, errors.New("limiter state is required for durable WireGuard peers but the snapshot is missing")
	}
	return snapshots, nil
}

// WithPersistentInboundSnapshots holds the same process-wide transaction lock
// used by limiter deliveries while fn validates, restores, and starts the
// embedded runtime. This prevents a concurrent delivery from leaving disk and
// runtime on different snapshot generations during startup.
func WithPersistentInboundSnapshots(fn func([]PersistentInboundSnapshot) error) error {
	persistentSnapshots.Lock()
	defer persistentSnapshots.Unlock()
	snapshots, err := loadPersistentInboundSnapshotsLocked()
	if err != nil {
		return err
	}
	return fn(snapshots)
}

// WithPersistentStateLock serializes embedded runtime lifecycle changes with
// snapshot delivery without requiring the current snapshot to be readable.
// Stop must remain possible even when corrupt state intentionally blocks Start.
func WithPersistentStateLock(fn func() error) error {
	persistentSnapshots.Lock()
	defer persistentSnapshots.Unlock()
	return fn()
}

func writePersistentFileAtomic(path, tempPattern string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	closed := false
	defer os.Remove(tmpPath)
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func writePersistentSnapshots(path string, snapshots []PersistentInboundSnapshot) error {
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].InboundTag < snapshots[j].InboundTag
	})
	data, err := json.MarshalIndent(persistentSnapshotFile{Version: persistentSnapshotVersion, Inbounds: snapshots}, "", "  ")
	if err != nil {
		return err
	}
	return writePersistentFileAtomic(path, ".limiter-state-*", data)
}

func writePersistentRequiredMarker(path string) error {
	data, err := json.Marshal(persistentRequiredMarker{Version: persistentMarkerVersion})
	if err != nil {
		return err
	}
	return writePersistentFileAtomic(path, ".limiter-required-*", data)
}

// PersistInboundSnapshot atomically records one inbound before its limiter
// delivery is acknowledged. Empty users/peers are retained to clear stale
// state on the next restart.
func PersistInboundSnapshot(snapshot PersistentInboundSnapshot) error {
	if err := validatePersistentInboundSnapshot(snapshot); err != nil {
		return err
	}
	persistentSnapshots.Lock()
	defer persistentSnapshots.Unlock()
	return persistInboundSnapshotLocked(snapshot)
}

func persistInboundSnapshotLocked(snapshot PersistentInboundSnapshot) error {
	if persistentSnapshots.path == "" {
		return errors.New("durable limiter snapshot path is not configured")
	}
	snapshots, _, err := readPersistentSnapshots(persistentSnapshots.path)
	if err != nil {
		return err
	}
	snapshots = replacePersistentInboundSnapshot(snapshots, snapshot)
	return writePersistentSnapshots(persistentSnapshots.path, snapshots)
}

func replacePersistentInboundSnapshot(
	snapshots []PersistentInboundSnapshot,
	snapshot PersistentInboundSnapshot,
) []PersistentInboundSnapshot {
	snapshots = append([]PersistentInboundSnapshot(nil), snapshots...)
	replaced := false
	for i := range snapshots {
		if snapshots[i].InboundTag == snapshot.InboundTag {
			snapshots[i] = snapshot
			replaced = true
			break
		}
	}
	if !replaced {
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

// PersistAndApplyInboundSnapshot atomically orders one durable snapshot before
// its in-memory replacement. Concurrent HTTP and WebSocket deliveries cannot
// interleave a newer disk snapshot with an older runtime Sync.
func PersistAndApplyInboundSnapshot(snapshot PersistentInboundSnapshot, apply func() error) error {
	if err := validatePersistentInboundSnapshot(snapshot); err != nil {
		return err
	}
	persistentSnapshots.Lock()
	defer persistentSnapshots.Unlock()
	if persistentSnapshots.path == "" {
		return errors.New("durable limiter snapshot path is not configured")
	}
	previous, existed, err := readPersistentSnapshots(persistentSnapshots.path)
	if err != nil {
		return err
	}
	updated := replacePersistentInboundSnapshot(previous, snapshot)
	if err := writePersistentSnapshots(persistentSnapshots.path, updated); err != nil {
		return err
	}
	if apply != nil {
		if err := apply(); err != nil {
			rollbackErr := restorePersistentSnapshotsLocked(previous, existed)
			if rollbackErr != nil {
				return fmt.Errorf("apply limiter snapshot: %v; snapshot rollback failed: %w", err, rollbackErr)
			}
			return err
		}
	}
	return nil
}

func restorePersistentSnapshotsLocked(snapshots []PersistentInboundSnapshot, existed bool) error {
	if existed {
		return writePersistentSnapshots(persistentSnapshots.path, append([]PersistentInboundSnapshot(nil), snapshots...))
	}
	if err := os.Remove(persistentSnapshots.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	directory, err := os.Open(filepath.Dir(persistentSnapshots.path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func removePersistentFileDurable(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func persistentSnapshotsHaveWireGuardPeers(snapshots []PersistentInboundSnapshot) bool {
	for _, snapshot := range snapshots {
		if len(snapshot.WireGuardPeers) > 0 {
			return true
		}
	}
	return false
}

func removePersistentInboundSnapshot(
	snapshots []PersistentInboundSnapshot,
	tag string,
) (updated []PersistentInboundSnapshot, found bool, wireGuard bool) {
	updated = make([]PersistentInboundSnapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if snapshot.InboundTag == tag {
			found = true
			wireGuard = wireGuard || len(snapshot.WireGuardPeers) > 0
			continue
		}
		updated = append(updated, snapshot)
	}
	return updated, found, wireGuard
}

func restorePersistentWireGuardDeleteLocked(
	snapshots []PersistentInboundSnapshot,
	snapshotsExisted bool,
	markerExisted bool,
) error {
	var failures []string
	if err := restorePersistentSnapshotsLocked(snapshots, snapshotsExisted); err != nil {
		failures = append(failures, "snapshot: "+err.Error())
	}
	if markerExisted {
		if err := writePersistentRequiredMarker(persistentSnapshots.markerPath); err != nil {
			failures = append(failures, "required marker: "+err.Error())
		}
	} else if err := removePersistentFileDurable(persistentSnapshots.markerPath); err != nil {
		failures = append(failures, "required marker: "+err.Error())
	}
	if len(failures) != 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

// DeleteWireGuardInboundState serializes durable and in-memory identity
// cleanup with limiter delivery and embedded runtime lifecycle operations.
// force must be true when the removed durable Xray inbound was WireGuard;
// otherwise a stale persisted mapping or sticky runtime identity requirement
// can still opt the tag into cleanup. runtime is evaluated while the
// persistence lock is held and may be nil for external Xray mode.
func DeleteWireGuardInboundState(tag string, force bool, runtime func() (*Limiter, error)) error {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return errors.New("WireGuard limiter cleanup requires an inbound tag")
	}

	persistentSnapshots.Lock()
	defer persistentSnapshots.Unlock()

	var runtimeLimiter *Limiter
	if runtime != nil {
		var err error
		runtimeLimiter, err = runtime()
		if err != nil {
			return err
		}
	}
	runtimeRequiresCleanup := runtimeLimiter != nil && runtimeLimiter.HasWireGuardPeerMappings(tag)
	if persistentSnapshots.path == "" || persistentSnapshots.markerPath == "" {
		if force || runtimeRequiresCleanup {
			return errors.New("durable limiter snapshot path is not configured")
		}
		return nil
	}

	previous, snapshotsExisted, err := readPersistentSnapshots(persistentSnapshots.path)
	if err != nil {
		return err
	}
	markerExisted, err := readPersistentRequiredMarker(persistentSnapshots.markerPath)
	if err != nil {
		return err
	}
	if markerExisted && !snapshotsExisted {
		return errors.New("limiter state is required for durable WireGuard peers but the snapshot is missing")
	}
	updated, snapshotFound, snapshotWasWireGuard := removePersistentInboundSnapshot(previous, tag)
	if !force && !snapshotWasWireGuard && !runtimeRequiresCleanup {
		return nil
	}

	if snapshotFound {
		if err := writePersistentSnapshots(persistentSnapshots.path, updated); err != nil {
			rollbackErr := restorePersistentWireGuardDeleteLocked(previous, snapshotsExisted, markerExisted)
			if rollbackErr != nil {
				return fmt.Errorf("delete limiter snapshot: %v; rollback failed: %w", err, rollbackErr)
			}
			return fmt.Errorf("delete limiter snapshot: %w", err)
		}
	}
	if markerExisted && !persistentSnapshotsHaveWireGuardPeers(updated) {
		if err := removePersistentFileDurable(persistentSnapshots.markerPath); err != nil {
			rollbackErr := restorePersistentWireGuardDeleteLocked(previous, snapshotsExisted, markerExisted)
			if rollbackErr != nil {
				return fmt.Errorf("delete limiter required marker: %v; rollback failed: %w", err, rollbackErr)
			}
			return fmt.Errorf("delete limiter required marker: %w", err)
		}
	}
	if runtimeLimiter != nil {
		runtimeLimiter.DeleteInboundLimiter(tag)
	}
	return nil
}

// RequireWireGuardPeerMappings verifies that every dynamic WireGuard host
// address already belongs to a durable limiter snapshot, then writes the
// independent required marker before the peer can be persisted or activated.
func RequireWireGuardPeerMappings(inboundTag string, allowedIPs []string) error {
	tag := strings.TrimSpace(inboundTag)
	if tag == "" || len(allowedIPs) == 0 {
		return errors.New("durable WireGuard peer requires an inbound tag and allowed IPs")
	}
	persistentSnapshots.Lock()
	defer persistentSnapshots.Unlock()
	if persistentSnapshots.path == "" || persistentSnapshots.markerPath == "" {
		return errors.New("durable limiter snapshot path is not configured")
	}
	snapshots, exists, err := readPersistentSnapshots(persistentSnapshots.path)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("durable limiter snapshot is missing")
	}

	mapped := make(map[string]struct{})
	for _, snapshot := range snapshots {
		if strings.TrimSpace(snapshot.InboundTag) != tag {
			continue
		}
		for _, peer := range snapshot.WireGuardPeers {
			if address, ok := canonicalPersistentWireGuardHostIP(peer.Address); ok {
				mapped[address] = struct{}{}
			}
		}
	}
	for _, allowedIP := range allowedIPs {
		address, ok := canonicalPersistentWireGuardHostIP(allowedIP)
		if !ok {
			return fmt.Errorf("WireGuard allowed IP %q is not a host prefix", allowedIP)
		}
		if _, ok := mapped[address]; !ok {
			return fmt.Errorf("WireGuard allowed IP %s has no durable limiter mapping for inbound %s", allowedIP, tag)
		}
	}

	required, err := readPersistentRequiredMarker(persistentSnapshots.markerPath)
	if err != nil {
		return err
	}
	if required {
		return nil
	}
	return writePersistentRequiredMarker(persistentSnapshots.markerPath)
}
