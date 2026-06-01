package config

import "strings"

// NormalizeRoutingStrategy canonicalizes supported routing strategy names.
func NormalizeRoutingStrategy(strategy string) string {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "", "round-robin", "roundrobin", "rr":
		return "round-robin"
	case "fill-first", "fillfirst", "ff":
		return "fill-first"
	case "codex-quota-score":
		return "codex-quota-score"
	default:
		return "round-robin"
	}
}

// NormalizeRoutingPercent clamps optional routing percentage settings.
func NormalizeRoutingPercent(percent float64) float64 {
	if percent < 0 {
		return 0
	}
	if percent > 100 {
		return 100
	}
	return percent
}
