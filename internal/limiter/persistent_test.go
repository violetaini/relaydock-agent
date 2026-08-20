package limiter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func configurePersistentTestPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "limiter-state.json")
	ConfigurePersistentSnapshotPath(path)
	t.Cleanup(func() { ConfigurePersistentSnapshotPath("") })
	return path
}

func persistentTestSnapshot() PersistentInboundSnapshot {
	return PersistentInboundSnapshot{
		InboundTag:         "wg-inbound",
		NodeLimit:          1024,
		InboundSharedLimit: true,
		Users: []UserInfo{
			{UID: 7, Email: "alice@example.com", SpeedLimit: 512, DeviceLimit: 2, ConnGroup: "alice|node"},
			{UID: 0, Email: "probe@relaydock.internal", ConnGroup: "wireguard-probe|1"},
		},
		WireGuardPeers: []WireGuardPeerUser{
			{Address: "10.66.0.2/32", Email: "alice@example.com"},
			{Address: "10.66.0.1/32", Email: "probe@relaydock.internal"},
		},
	}
}

func TestPersistentInboundSnapshotRoundTripAndRequiredMarker(t *testing.T) {
	path := configurePersistentTestPath(t)
	want := persistentTestSnapshot()
	if err := PersistInboundSnapshot(want); err != nil {
		t.Fatalf("PersistInboundSnapshot: %v", err)
	}
	if err := RequireWireGuardPeerMappings(want.InboundTag, []string{"10.66.0.2/32"}); err != nil {
		t.Fatalf("RequireWireGuardPeerMappings: %v", err)
	}

	got, err := LoadPersistentInboundSnapshots()
	if err != nil {
		t.Fatalf("LoadPersistentInboundSnapshots: %v", err)
	}
	if !reflect.DeepEqual(got, []PersistentInboundSnapshot{want}) {
		t.Fatalf("snapshots=%#v want %#v", got, []PersistentInboundSnapshot{want})
	}
	if info, err := os.Stat(path + ".required"); err != nil {
		t.Fatalf("required marker: %v", err)
	} else if info.Mode().Perm() != 0600 {
		t.Fatalf("required marker mode=%o", info.Mode().Perm())
	}
}

func TestPersistentSnapshotFirstUpgradeWithoutMarkerOrStateStartsEmpty(t *testing.T) {
	configurePersistentTestPath(t)
	snapshots, err := LoadPersistentInboundSnapshots()
	if err != nil {
		t.Fatalf("LoadPersistentInboundSnapshots: %v", err)
	}
	if len(snapshots) != 0 {
		t.Fatalf("snapshots=%#v", snapshots)
	}
}

func TestPersistInboundSnapshotRequiresConfiguredPath(t *testing.T) {
	ConfigurePersistentSnapshotPath("")
	if err := PersistInboundSnapshot(persistentTestSnapshot()); err == nil {
		t.Fatal("PersistInboundSnapshot succeeded without a durable path")
	}
}

func TestPersistentSnapshotRejectsWireGuardMappingWithoutUserPolicy(t *testing.T) {
	configurePersistentTestPath(t)
	snapshot := persistentTestSnapshot()
	snapshot.Users = snapshot.Users[:1]
	err := PersistInboundSnapshot(snapshot)
	if err == nil || !strings.Contains(err.Error(), "no matching user policy") {
		t.Fatalf("PersistInboundSnapshot error=%v", err)
	}
}

func TestPersistAndApplyInboundSnapshotKeepsDiskAndRuntimeGenerationAligned(t *testing.T) {
	configurePersistentTestPath(t)
	const generations = 32
	var wg sync.WaitGroup
	var runtimeMu sync.Mutex
	runtimeEmail := ""
	for generation := 0; generation < generations; generation++ {
		email := fmt.Sprintf("user-%02d@example.com", generation)
		snapshot := PersistentInboundSnapshot{
			InboundTag: "wg",
			Users:      []UserInfo{{Email: email}},
			WireGuardPeers: []WireGuardPeerUser{
				{Address: "10.66.0.2/32", Email: email},
			},
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := PersistAndApplyInboundSnapshot(snapshot, func() error {
				runtimeMu.Lock()
				runtimeEmail = email
				runtimeMu.Unlock()
				return nil
			}); err != nil {
				t.Errorf("PersistAndApplyInboundSnapshot: %v", err)
			}
		}()
	}
	wg.Wait()

	snapshots, err := LoadPersistentInboundSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 || len(snapshots[0].Users) != 1 {
		t.Fatalf("snapshots=%#v", snapshots)
	}
	runtimeMu.Lock()
	gotRuntime := runtimeEmail
	runtimeMu.Unlock()
	if gotDisk := snapshots[0].Users[0].Email; gotDisk != gotRuntime {
		t.Fatalf("disk generation=%q runtime generation=%q", gotDisk, gotRuntime)
	}
}

func TestPersistAndApplyInboundSnapshotRollsBackDiskWhenApplyFails(t *testing.T) {
	configurePersistentTestPath(t)
	original := persistentTestSnapshot()
	if err := PersistInboundSnapshot(original); err != nil {
		t.Fatal(err)
	}
	replacement := original
	replacement.Users = append([]UserInfo(nil), original.Users...)
	replacement.Users[0].SpeedLimit = 4096
	err := PersistAndApplyInboundSnapshot(replacement, func() error {
		return fmt.Errorf("runtime unavailable")
	})
	if err == nil {
		t.Fatal("failed runtime apply was acknowledged")
	}
	snapshots, loadErr := LoadPersistentInboundSnapshots()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !reflect.DeepEqual(snapshots, []PersistentInboundSnapshot{original}) {
		t.Fatalf("failed apply left snapshot=%#v want %#v", snapshots, []PersistentInboundSnapshot{original})
	}
}

func TestPersistentSnapshotRequiredMarkerRejectsMissingOrCorruptState(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, path string)
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, path string) {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "corrupt",
			mutate: func(t *testing.T, path string) {
				if err := os.WriteFile(path, []byte("not-json"), 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := configurePersistentTestPath(t)
			snapshot := persistentTestSnapshot()
			if err := PersistInboundSnapshot(snapshot); err != nil {
				t.Fatal(err)
			}
			if err := RequireWireGuardPeerMappings(snapshot.InboundTag, []string{"10.66.0.2/32"}); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, path)
			if _, err := LoadPersistentInboundSnapshots(); err == nil {
				t.Fatal("required state failure was accepted")
			}
		})
	}
}

func TestRequireWireGuardPeerMappingsRejectsUnmappedAddressWithoutMarker(t *testing.T) {
	path := configurePersistentTestPath(t)
	snapshot := persistentTestSnapshot()
	if err := PersistInboundSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	err := RequireWireGuardPeerMappings(snapshot.InboundTag, []string{"10.66.0.99/32"})
	if err == nil || !strings.Contains(err.Error(), "no durable limiter mapping") {
		t.Fatalf("RequireWireGuardPeerMappings error=%v", err)
	}
	if _, err := os.Stat(path + ".required"); !os.IsNotExist(err) {
		t.Fatalf("unexpected required marker after rejected mapping: %v", err)
	}
}

func TestDeleteWireGuardInboundStateClearsSnapshotMarkerAndRuntime(t *testing.T) {
	path := configurePersistentTestPath(t)
	wgSnapshot := persistentTestSnapshot()
	otherSnapshot := PersistentInboundSnapshot{
		InboundTag: "vless-inbound",
		Users:      []UserInfo{{Email: "bob@example.com"}},
	}
	if err := PersistInboundSnapshot(wgSnapshot); err != nil {
		t.Fatal(err)
	}
	if err := PersistInboundSnapshot(otherSnapshot); err != nil {
		t.Fatal(err)
	}
	if err := RequireWireGuardPeerMappings(wgSnapshot.InboundTag, []string{"10.66.0.2/32"}); err != nil {
		t.Fatal(err)
	}
	runtime := New()
	runtime.AddInboundLimiter(wgSnapshot.InboundTag, wgSnapshot.NodeLimit, wgSnapshot.Users, wgSnapshot.WireGuardPeers...)

	err := DeleteWireGuardInboundState(wgSnapshot.InboundTag, true, func() (*Limiter, error) {
		return runtime, nil
	})
	if err != nil {
		t.Fatalf("DeleteWireGuardInboundState: %v", err)
	}
	if runtime.HasWireGuardPeerMappings(wgSnapshot.InboundTag) {
		t.Fatal("runtime WireGuard identity requirement survived deletion")
	}
	snapshots, err := LoadPersistentInboundSnapshots()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshots, []PersistentInboundSnapshot{otherSnapshot}) {
		t.Fatalf("snapshots=%#v want %#v", snapshots, []PersistentInboundSnapshot{otherSnapshot})
	}
	if _, err := os.Stat(path + ".required"); !os.IsNotExist(err) {
		t.Fatalf("required marker survived last WireGuard snapshot: %v", err)
	}
}

func TestDeleteWireGuardInboundStateDoesNotMutateWhenRuntimeUnavailable(t *testing.T) {
	path := configurePersistentTestPath(t)
	snapshot := persistentTestSnapshot()
	if err := PersistInboundSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := RequireWireGuardPeerMappings(snapshot.InboundTag, []string{"10.66.0.2/32"}); err != nil {
		t.Fatal(err)
	}

	err := DeleteWireGuardInboundState(snapshot.InboundTag, true, func() (*Limiter, error) {
		return nil, errors.New("runtime limiter unavailable")
	})
	if err == nil || !strings.Contains(err.Error(), "runtime limiter unavailable") {
		t.Fatalf("DeleteWireGuardInboundState error=%v", err)
	}
	snapshots, loadErr := LoadPersistentInboundSnapshots()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if !reflect.DeepEqual(snapshots, []PersistentInboundSnapshot{snapshot}) {
		t.Fatalf("failed cleanup mutated snapshots=%#v", snapshots)
	}
	if _, statErr := os.Stat(path + ".required"); statErr != nil {
		t.Fatalf("failed cleanup removed required marker: %v", statErr)
	}
}
