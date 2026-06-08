package cliproxy

import (
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestSelectorFromRoutingConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.Config
		want any
	}{
		{name: "default", cfg: &config.Config{}, want: &coreauth.RoundRobinSelector{}},
		{name: "fill-first", cfg: &config.Config{Routing: config.RoutingConfig{Strategy: "fillfirst"}}, want: &coreauth.FillFirstSelector{}},
		{name: "codex-quota-score", cfg: &config.Config{Routing: config.RoutingConfig{Strategy: "codex-quota-score"}}, want: &coreauth.CodexQuotaScoreSelector{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := selectorFromRoutingConfig(tc.cfg)
			switch tc.want.(type) {
			case *coreauth.RoundRobinSelector:
				if _, ok := got.(*coreauth.RoundRobinSelector); !ok {
					t.Fatalf("selector type = %T, want RoundRobinSelector", got)
				}
			case *coreauth.FillFirstSelector:
				fillFirst, ok := got.(*coreauth.FillFirstSelector)
				if !ok {
					t.Fatalf("selector type = %T, want FillFirstSelector", got)
				}
				if tc.cfg != nil && tc.cfg.Routing.FillFirstThresholdPercent != 0 && fillFirst.ThresholdPercent != tc.cfg.Routing.FillFirstThresholdPercent {
					t.Fatalf("FillFirstSelector.ThresholdPercent = %v, want %v", fillFirst.ThresholdPercent, tc.cfg.Routing.FillFirstThresholdPercent)
				}
			case *coreauth.CodexQuotaScoreSelector:
				codexQuotaScore, ok := got.(*coreauth.CodexQuotaScoreSelector)
				if !ok {
					t.Fatalf("selector type = %T, want CodexQuotaScoreSelector", got)
				}
				if tc.cfg != nil && tc.cfg.Routing.CodexQuotaScoreThresholdPercent != 0 && codexQuotaScore.ThresholdPercent != tc.cfg.Routing.CodexQuotaScoreThresholdPercent {
					t.Fatalf("CodexQuotaScoreSelector.ThresholdPercent = %v, want %v", codexQuotaScore.ThresholdPercent, tc.cfg.Routing.CodexQuotaScoreThresholdPercent)
				}
			}
		})
	}
}

func TestSelectorFromRoutingConfig_FillFirstThreshold(t *testing.T) {
	t.Parallel()

	got := selectorFromRoutingConfig(&config.Config{Routing: config.RoutingConfig{
		Strategy:                  "fill-first",
		FillFirstThresholdPercent: 90,
	}})
	fillFirst, ok := got.(*coreauth.FillFirstSelector)
	if !ok {
		t.Fatalf("selector type = %T, want FillFirstSelector", got)
	}
	if fillFirst.ThresholdPercent != 90 {
		t.Fatalf("ThresholdPercent = %v, want 90", fillFirst.ThresholdPercent)
	}
}

func TestSelectorFromRoutingConfig_CodexQuotaScoreThreshold(t *testing.T) {
	t.Parallel()

	got := selectorFromRoutingConfig(&config.Config{Routing: config.RoutingConfig{
		Strategy:                        "codex-quota-score",
		CodexQuotaScoreThresholdPercent: 90,
	}})
	codexQuotaScore, ok := got.(*coreauth.CodexQuotaScoreSelector)
	if !ok {
		t.Fatalf("selector type = %T, want CodexQuotaScoreSelector", got)
	}
	if codexQuotaScore.ThresholdPercent != 90 {
		t.Fatalf("ThresholdPercent = %v, want 90", codexQuotaScore.ThresholdPercent)
	}
}

func TestSelectorFromRoutingConfig_WithSessionAffinityWrapsFallback(t *testing.T) {
	t.Parallel()

	got := selectorFromRoutingConfig(&config.Config{Routing: config.RoutingConfig{
		Strategy:        "codex-quota-score",
		SessionAffinity: true,
	}})
	if _, ok := got.(*coreauth.SessionAffinitySelector); !ok {
		t.Fatalf("selector type = %T, want SessionAffinitySelector", got)
	}
}
