package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeedLocalGeoDataCopiesCustomExtDatFiles(t *testing.T) {
	root := t.TempDir()
	destDir := filepath.Join(root, "agent", "bin")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Pre-existing standard file must not be overwritten.
	existingGeoIP := filepath.Join(destDir, "geoip.dat")
	if err := os.WriteFile(existingGeoIP, []byte("existing-geoip"), 0o644); err != nil {
		t.Fatal(err)
	}

	backupDir := filepath.Join(root, "backup_xui_hk", "x-ui", "bin")
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "geoip.dat"), []byte("backup-geoip"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "geosite_IR.dat"), []byte("ir-sites"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "geoip_IR.dat"), []byte("ir-ips"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Empty file and unrelated binary should be ignored.
	if err := os.WriteFile(filepath.Join(backupDir, "geosite_VN.dat"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "xray-linux-amd64"), []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}

	seedLocalGeoData(destDir, []string{filepath.Join(root, "backup_xui*", "x-ui", "bin")})

	gotExisting, err := os.ReadFile(existingGeoIP)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotExisting) != "existing-geoip" {
		t.Fatalf("existing geoip.dat overwritten: %q", string(gotExisting))
	}

	for name, want := range map[string]string{
		"geosite_IR.dat": "ir-sites",
		"geoip_IR.dat":   "ir-ips",
	} {
		got, err := os.ReadFile(filepath.Join(destDir, name))
		if err != nil {
			t.Fatalf("expected %s to be seeded: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s mismatch: got %q want %q", name, string(got), want)
		}
	}

	if _, err := os.Stat(filepath.Join(destDir, "geosite_VN.dat")); !os.IsNotExist(err) {
		t.Fatalf("expected empty geosite_VN.dat to be skipped")
	}
	if _, err := os.Stat(filepath.Join(destDir, "xray-linux-amd64")); !os.IsNotExist(err) {
		t.Fatalf("expected non-dat file to be skipped")
	}
}
