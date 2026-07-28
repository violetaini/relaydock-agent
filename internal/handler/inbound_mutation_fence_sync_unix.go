//go:build !windows

package handler

import (
	"os"
	"path/filepath"
)

func syncInboundMutationFenceParent(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
