package version

import (
	"fmt"
	"strconv"
	"strings"
)

// CompareStable compares two stable X.Y.Z versions. A leading "v" is accepted
// for release tags. Unknown or pre-release version formats are rejected so
// callers can fail closed before replacing an installed binary.
func CompareStable(a, b string) (int, error) {
	av, err := parseStable(a)
	if err != nil {
		return 0, fmt.Errorf("parse first version: %w", err)
	}
	bv, err := parseStable(b)
	if err != nil {
		return 0, fmt.Errorf("parse second version: %w", err)
	}
	for i := range av {
		if av[i] < bv[i] {
			return -1, nil
		}
		if av[i] > bv[i] {
			return 1, nil
		}
	}
	return 0, nil
}

// NormalizeStable returns a canonical X.Y.Z form for a stable release tag.
func NormalizeStable(raw string) (string, error) {
	v, err := parseStable(raw)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]), nil
}

func parseStable(raw string) ([3]uint64, error) {
	var out [3]uint64
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "v") {
		s = strings.TrimPrefix(s, "v")
	}
	parts := strings.Split(s, ".")
	if len(parts) != len(out) {
		return out, fmt.Errorf("must be stable X.Y.Z, got %q", raw)
	}
	for i, part := range parts {
		if part == "" {
			return out, fmt.Errorf("must be stable X.Y.Z, got %q", raw)
		}
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return out, fmt.Errorf("must be stable X.Y.Z, got %q", raw)
		}
		out[i] = value
	}
	return out, nil
}
