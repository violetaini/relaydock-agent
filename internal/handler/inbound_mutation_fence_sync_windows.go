//go:build windows

package handler

// Windows does not expose a portable directory fsync through os.File. The
// atomic rename still prevents partial JSON; the file itself is synced before
// replacement by writeInboundMutationFenceFileAtomic.
func syncInboundMutationFenceParent(string) error {
	return nil
}
