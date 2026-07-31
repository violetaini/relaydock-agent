package agent

import (
	"testing"

	"github.com/violetaini/relaydock-agent/internal/constants"
)

func TestAdvertisedCapabilitiesIncludeXrayVersionSelection(t *testing.T) {
	for _, rpcAvailable := range []bool{false, true} {
		capabilities := advertisedCapabilities(rpcAvailable, false)
		if !capabilities[constants.CapabilityXrayVersionSelectV1] {
			t.Fatalf("rpcAvailable=%v capabilities=%v", rpcAvailable, capabilities)
		}
	}
}
