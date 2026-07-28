package version

import "testing"

func TestCompareStable(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{name: "equal with tag prefix", a: "0.4.3", b: "v0.4.3", want: 0},
		{name: "patch upgrade", a: "0.4.3", b: "0.4.4", want: -1},
		{name: "minor downgrade", a: "0.5.0", b: "0.4.9", want: 1},
		{name: "numeric comparison", a: "0.4.10", b: "0.4.9", want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CompareStable(tt.a, tt.b)
			if err != nil {
				t.Fatalf("CompareStable(%q, %q): %v", tt.a, tt.b, err)
			}
			if got != tt.want {
				t.Fatalf("CompareStable(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCompareStableRejectsUnknownFormats(t *testing.T) {
	for _, raw := range []string{"", "0.4", "0.4.3-beta", "v0.4.3.1", "0.x.3"} {
		if _, err := CompareStable(raw, "0.4.3"); err == nil {
			t.Fatalf("CompareStable(%q, current) succeeded for malformed version", raw)
		}
		if _, err := NormalizeStable(raw); err == nil {
			t.Fatalf("NormalizeStable(%q) succeeded for malformed version", raw)
		}
	}
}

func TestNormalizeStable(t *testing.T) {
	got, err := NormalizeStable(" v01.002.0003 ")
	if err != nil {
		t.Fatal(err)
	}
	if got != "1.2.3" {
		t.Fatalf("NormalizeStable = %q, want 1.2.3", got)
	}
}
