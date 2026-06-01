package config

import "testing"

func TestNormalizeRoutingStrategy(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"":                  "round-robin",
		"round-robin":       "round-robin",
		"fillfirst":         "fill-first",
		"FF":                "fill-first",
		"codex-quota-score": "codex-quota-score",
		"unknown":           "round-robin",
	}

	for input, want := range tests {
		if got := NormalizeRoutingStrategy(input); got != want {
			t.Fatalf("NormalizeRoutingStrategy(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeRoutingPercent(t *testing.T) {
	t.Parallel()

	tests := map[float64]float64{
		-1:  0,
		0:   0,
		90:  90,
		101: 100,
	}

	for input, want := range tests {
		if got := NormalizeRoutingPercent(input); got != want {
			t.Fatalf("NormalizeRoutingPercent(%v) = %v, want %v", input, got, want)
		}
	}
}

func TestParseConfigBytes_NormalizesRoutingStrategy(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfigBytes([]byte("routing:\n  strategy: fillfirst\n"))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if cfg.Routing.Strategy != "fill-first" {
		t.Fatalf("Routing.Strategy = %q, want fill-first", cfg.Routing.Strategy)
	}

	cfg, err = ParseConfigBytes([]byte("routing:\n  strategy: codex-quota-score\n"))
	if err != nil {
		t.Fatalf("ParseConfigBytes() codex error = %v", err)
	}
	if cfg.Routing.Strategy != "codex-quota-score" {
		t.Fatalf("Routing.Strategy = %q, want codex-quota-score", cfg.Routing.Strategy)
	}
}

func TestParseConfigBytes_NormalizesFillFirstThresholdPercent(t *testing.T) {
	t.Parallel()

	cfg, err := ParseConfigBytes([]byte("routing:\n  strategy: fill-first\n  fill-first-threshold-percent: 120\n"))
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if cfg.Routing.FillFirstThresholdPercent != 100 {
		t.Fatalf("Routing.FillFirstThresholdPercent = %v, want 100", cfg.Routing.FillFirstThresholdPercent)
	}
}
