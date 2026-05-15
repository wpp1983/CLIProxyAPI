package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestCodexExecutorRefresh_MapsQuotaStateAndCooldown(t *testing.T) {
	t.Parallel()

	blockedUntil := time.Now().Add(12 * time.Minute).UTC().Truncate(time.Second)
	weeklyReset := time.Now().Add(5 * 24 * time.Hour).UTC().Truncate(time.Second)
	fiveHourReset := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backend-api/codex/usage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"quota":{"five_hour":{"remaining":4,"limit":40,"reset_at":"` + fiveHourReset.Format(time.RFC3339) + `"},"weekly":{"remaining":80,"limit":100,"reset_at":"` + weeklyReset.Format(time.RFC3339) + `"},"blocked_until":"` + blockedUntil.Format(time.RFC3339) + `"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{
			"email":        "user@example.com",
			"access_token": "token-123",
		},
		Unavailable:    true,
		NextRetryAfter: time.Now().Add(30 * time.Minute),
		Quota: cliproxyauth.QuotaState{
			Exceeded:      true,
			Reason:        "quota",
			NextRecoverAt: time.Now().Add(30 * time.Minute),
		},
		Attributes: map[string]string{
			"base_url": server.URL + "/backend-api/codex",
		},
	}

	updated, err := executor.Refresh(context.Background(), auth)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	quota, ok := updated.GetCodexQuotaState()
	if !ok {
		t.Fatal("GetCodexQuotaState() ok = false, want true")
	}
	if quota.LastRefreshAt == nil || quota.LastRefreshAt.IsZero() {
		t.Fatal("LastRefreshAt = nil/zero, want set")
	}
	if quota.RefreshStatus != "ok" || quota.RefreshError != "" {
		t.Fatalf("quota refresh metadata = status %q error %q, want ok/empty", quota.RefreshStatus, quota.RefreshError)
	}
	if quota.FiveHour.Remaining == nil || *quota.FiveHour.Remaining != 4 {
		t.Fatalf("FiveHour.Remaining = %#v, want 4", quota.FiveHour.Remaining)
	}
	if quota.Weekly.Remaining == nil || *quota.Weekly.Remaining != 80 {
		t.Fatalf("Weekly.Remaining = %#v, want 80", quota.Weekly.Remaining)
	}
	if !updated.Unavailable || !updated.NextRetryAfter.Equal(blockedUntil) {
		t.Fatalf("auth cooldown = unavailable %v next %s, want true/%s", updated.Unavailable, updated.NextRetryAfter, blockedUntil)
	}
	if !updated.Quota.Exceeded || updated.Quota.Reason != "quota" || !updated.Quota.NextRecoverAt.Equal(blockedUntil) {
		t.Fatalf("auth quota = %#v, want blocked-until propagated", updated.Quota)
	}
	if got := updated.Metadata[cliproxyauth.CodexQuotaRefreshIntervalSecondsKey]; got != int(cliproxyauth.CodexQuotaRefreshInterval/time.Second) {
		t.Fatalf("refresh interval metadata = %#v, want %d", got, int(cliproxyauth.CodexQuotaRefreshInterval/time.Second))
	}
}

func TestCodexExecutorRefresh_UsesUsageEndpointAndParsesUsageWindows(t *testing.T) {
	t.Parallel()

	blockedUntil := time.Now().Add(25 * time.Minute).UTC().Truncate(time.Second)
	weeklyReset := time.Now().Add(6 * 24 * time.Hour).UTC().Truncate(time.Second)
	fiveHourReset := time.Now().Add(4 * time.Hour).UTC().Truncate(time.Second)
	var usageRequests atomic.Int32
	var otherRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/backend-api/codex/usage":
			usageRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rate_limit":{"primary_window":{"remaining":81,"limit":100,"reset_at":"` + weeklyReset.Format(time.RFC3339) + `"},"secondary_window":{"remaining":7,"limit":40,"reset_at":"` + fiveHourReset.Format(time.RFC3339) + `","blocked_until":"` + blockedUntil.Format(time.RFC3339) + `"},"additional_rate_limits":[{"window_name":"five_hour","remaining":7,"limit":40,"reset_at":"` + fiveHourReset.Format(time.RFC3339) + `"}]}}`))
		default:
			otherRequests.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{
			"email":        "user@example.com",
			"access_token": "token-123",
		},
		Attributes: map[string]string{
			"base_url": server.URL + "/backend-api/codex",
		},
	}

	updated, err := executor.Refresh(context.Background(), auth)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := usageRequests.Load(); got != 1 {
		t.Fatalf("usage endpoint requests = %d, want 1", got)
	}
	if got := otherRequests.Load(); got != 0 {
		t.Fatalf("non-usage endpoint requests = %d, want 0", got)
	}
	quota, ok := updated.GetCodexQuotaState()
	if !ok {
		t.Fatal("GetCodexQuotaState() ok = false, want true")
	}
	if quota.Weekly.Remaining == nil || *quota.Weekly.Remaining != 81 {
		t.Fatalf("Weekly.Remaining = %#v, want 81", quota.Weekly.Remaining)
	}
	if quota.FiveHour.Remaining == nil || *quota.FiveHour.Remaining != 7 {
		t.Fatalf("FiveHour.Remaining = %#v, want 7", quota.FiveHour.Remaining)
	}
	if quota.Weekly.ResetAt == nil || !quota.Weekly.ResetAt.Equal(weeklyReset) {
		t.Fatalf("Weekly.ResetAt = %v, want %v", quota.Weekly.ResetAt, weeklyReset)
	}
	if quota.FiveHour.ResetAt == nil || !quota.FiveHour.ResetAt.Equal(fiveHourReset) {
		t.Fatalf("FiveHour.ResetAt = %v, want %v", quota.FiveHour.ResetAt, fiveHourReset)
	}
	if !updated.Unavailable || !updated.NextRetryAfter.Equal(blockedUntil) {
		t.Fatalf("auth cooldown = unavailable %v next %s, want true/%s", updated.Unavailable, updated.NextRetryAfter, blockedUntil)
	}
}

func TestCodexExecutorRefresh_PreservesPriorWindowsOnQuotaFetchFailure(t *testing.T) {
	t.Parallel()

	weeklyReset := time.Now().Add(3 * 24 * time.Hour).UTC().Truncate(time.Second)
	lastRefresh := time.Now().Add(-10 * time.Minute).UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{
			"email":        "user@example.com",
			"access_token": "token-123",
		},
		Attributes: map[string]string{
			"base_url": server.URL + "/backend-api/codex",
		},
	}
	auth.SetCodexQuotaState(cliproxyauth.CodexQuotaState{
		Weekly: cliproxyauth.CodexQuotaBucket{
			Remaining: float64Ptr(42),
			Limit:     float64Ptr(100),
			ResetAt:   &weeklyReset,
		},
		LastRefreshAt: &lastRefresh,
		RefreshStatus: "ok",
	})

	updated, err := executor.Refresh(context.Background(), auth)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	quota, ok := updated.GetCodexQuotaState()
	if !ok {
		t.Fatal("GetCodexQuotaState() ok = false, want true")
	}
	if quota.Weekly.Remaining == nil || *quota.Weekly.Remaining != 42 {
		t.Fatalf("Weekly.Remaining = %#v, want preserved 42", quota.Weekly.Remaining)
	}
	if quota.LastRefreshAt == nil || !quota.LastRefreshAt.Equal(lastRefresh) {
		t.Fatalf("LastRefreshAt = %v, want preserved %v on failure", quota.LastRefreshAt, lastRefresh)
	}
	if quota.RefreshStatus != "error" {
		t.Fatalf("RefreshStatus = %q, want error", quota.RefreshStatus)
	}
	if quota.RefreshError == "" {
		t.Fatal("RefreshError = empty, want failure detail")
	}
	if updated.Unavailable {
		t.Fatal("Unavailable = true, want prior quota windows preserved without inventing new cooldown")
	}
}

func TestCodexExecutorRefresh_SkipsPhase3QuotaEnrichmentForAPIKeyAuth(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.NotFound(w, r)
	}))
	defer server.Close()

	executor := NewCodexExecutor(&config.Config{})
	originalRetry := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	originalRecover := time.Now().Add(45 * time.Minute).UTC().Truncate(time.Second)
	auth := &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{
			"email": "",
		},
		Attributes: map[string]string{
			"api_key":  "sk-test",
			"base_url": server.URL + "/backend-api/codex",
		},
		Unavailable:    true,
		NextRetryAfter: originalRetry,
		Quota: cliproxyauth.QuotaState{
			Exceeded:      true,
			Reason:        "quota",
			NextRecoverAt: originalRecover,
		},
	}

	updated, err := executor.Refresh(context.Background(), auth)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("quota probe requests = %d, want 0", got)
	}
	if _, ok := updated.GetCodexQuotaState(); ok {
		t.Fatal("GetCodexQuotaState() ok = true, want false for api-key auth")
	}
	if _, ok := updated.Metadata[cliproxyauth.CodexQuotaRefreshIntervalSecondsKey]; ok {
		t.Fatalf("refresh interval metadata present = %#v, want absent", updated.Metadata[cliproxyauth.CodexQuotaRefreshIntervalSecondsKey])
	}
	if !updated.Unavailable || !updated.NextRetryAfter.Equal(originalRetry) {
		t.Fatalf("auth cooldown = unavailable %v next %s, want true/%s", updated.Unavailable, updated.NextRetryAfter, originalRetry)
	}
	if !updated.Quota.Exceeded || updated.Quota.Reason != "quota" || !updated.Quota.NextRecoverAt.Equal(originalRecover) {
		t.Fatalf("auth quota = %#v, want unchanged", updated.Quota)
	}
	if _, ok := updated.Metadata["last_refresh"]; !ok {
		t.Fatal("last_refresh metadata missing, want preserved unrelated refresh behavior")
	}
}

func float64Ptr(v float64) *float64 {
	return &v
}
