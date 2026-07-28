package agent

import "testing"

func TestReloadCertServicesUsesInjectedXrayRestart(t *testing.T) {
	for _, target := range []string{"xray", "both"} {
		t.Run(target, func(t *testing.T) {
			nginxCalls := 0
			xrayCalls := 0
			err := reloadCertServices(
				target,
				func() error { nginxCalls++; return nil },
				func() error { xrayCalls++; return nil },
			)
			if err != nil {
				t.Fatalf("reload services: %v", err)
			}
			if xrayCalls != 1 {
				t.Fatalf("xray restart calls=%d want 1", xrayCalls)
			}
			wantNginx := 0
			if target == "both" {
				wantNginx = 1
			}
			if nginxCalls != wantNginx {
				t.Fatalf("nginx reload calls=%d want %d", nginxCalls, wantNginx)
			}
		})
	}
}

func TestReloadCertServicesFailsClosedWithoutXrayRestartHandler(t *testing.T) {
	if err := reloadCertServices("xray", func() error { return nil }, nil); err == nil {
		t.Fatal("xray certificate reload succeeded without the serialized restart handler")
	}
}
