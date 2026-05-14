package management

import "testing"

func TestNormalizeRoutingStrategy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		want string
		ok   bool
	}{
		"":                  {want: "round-robin", ok: true},
		"roundrobin":        {want: "round-robin", ok: true},
		"fillfirst":         {want: "fill-first", ok: true},
		"codex-quota-score": {want: "codex-quota-score", ok: true},
		"bogus":             {want: "", ok: false},
	}

	for input, want := range tests {
		got, ok := normalizeRoutingStrategy(input)
		if got != want.want || ok != want.ok {
			t.Fatalf("normalizeRoutingStrategy(%q) = (%q, %v), want (%q, %v)", input, got, ok, want.want, want.ok)
		}
	}
}
