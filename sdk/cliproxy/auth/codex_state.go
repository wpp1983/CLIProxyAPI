package auth

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	CodexQuotaMetadataKey               = "codex_quota"
	CodexManualScoreAdjustmentKey       = "codex_manual_score_adjustment"
	CodexComputedScoreMetadataKey       = "codex_computed_score"
	CodexScoreReasonMetadataKey         = "codex_score_reason"
	CodexLastSelectionReasonMetadataKey = "codex_last_selection_reason"
	CodexQuotaRefreshIntervalSecondsKey = "refresh_interval_seconds"
)

const CodexQuotaRefreshInterval = 15 * time.Minute

type CodexQuotaBucket struct {
	Remaining *float64   `json:"remaining,omitempty"`
	Limit     *float64   `json:"limit,omitempty"`
	ResetAt   *time.Time `json:"reset_at,omitempty"`
}

type CodexQuotaState struct {
	FiveHour      CodexQuotaBucket `json:"five_hour,omitempty"`
	Weekly        CodexQuotaBucket `json:"weekly,omitempty"`
	LastRefreshAt *time.Time       `json:"last_refresh_at,omitempty"`
	RefreshStatus string           `json:"refresh_status,omitempty"`
	RefreshError  string           `json:"refresh_error,omitempty"`
}

func (b CodexQuotaBucket) clone() CodexQuotaBucket {
	cloned := CodexQuotaBucket{}
	if b.Remaining != nil {
		cloned.Remaining = float64Ptr(*b.Remaining)
	}
	if b.Limit != nil {
		cloned.Limit = float64Ptr(*b.Limit)
	}
	if b.ResetAt != nil {
		resetAt := b.ResetAt.UTC()
		cloned.ResetAt = &resetAt
	}
	return cloned
}

func (s CodexQuotaState) clone() CodexQuotaState {
	cloned := CodexQuotaState{
		FiveHour:      s.FiveHour.clone(),
		Weekly:        s.Weekly.clone(),
		RefreshStatus: s.RefreshStatus,
		RefreshError:  s.RefreshError,
	}
	if s.LastRefreshAt != nil {
		lastRefresh := s.LastRefreshAt.UTC()
		cloned.LastRefreshAt = &lastRefresh
	}
	return cloned
}

func (a *Auth) GetCodexQuotaState() (CodexQuotaState, bool) {
	if a == nil || a.Metadata == nil {
		return CodexQuotaState{}, false
	}
	state, ok := codexQuotaStateFromAny(a.Metadata[CodexQuotaMetadataKey])
	if ok {
		a.Metadata[CodexQuotaMetadataKey] = state.metadataValue()
	} else {
		delete(a.Metadata, CodexQuotaMetadataKey)
	}
	return state, ok
}

func (a *Auth) SetCodexQuotaState(state CodexQuotaState) {
	if a == nil {
		return
	}
	a.ensureMetadata()
	a.Metadata[CodexQuotaMetadataKey] = state.metadataValue()
	if a.Metadata[CodexQuotaMetadataKey] == nil {
		delete(a.Metadata, CodexQuotaMetadataKey)
	}
}

func (a *Auth) CodexManualScoreAdjustment() (float64, bool) {
	return a.readCodexFloat(CodexManualScoreAdjustmentKey)
}

func (a *Auth) SetCodexManualScoreAdjustment(value float64) {
	a.writeCodexFloat(CodexManualScoreAdjustmentKey, value)
}

func (a *Auth) CodexComputedScore() (float64, bool) {
	return a.readCodexFloat(CodexComputedScoreMetadataKey)
}

func (a *Auth) SetCodexComputedScore(value float64) {
	a.writeCodexFloat(CodexComputedScoreMetadataKey, value)
}

func (a *Auth) CodexScoreReason() string {
	return a.readCodexString(CodexScoreReasonMetadataKey)
}

func (a *Auth) SetCodexScoreReason(reason string) {
	a.writeCodexString(CodexScoreReasonMetadataKey, reason)
}

func (a *Auth) CodexLastSelectionReason() string {
	return a.readCodexString(CodexLastSelectionReasonMetadataKey)
}

func (a *Auth) SetCodexLastSelectionReason(reason string) {
	a.writeCodexString(CodexLastSelectionReasonMetadataKey, reason)
}

func IsCodexOAuthLikeAuth(a *Auth) bool {
	if a == nil || !strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
		return false
	}
	kind, _ := a.AccountInfo()
	return !strings.EqualFold(strings.TrimSpace(kind), "api_key")
}

func EnsureCodexQuotaRefreshMetadata(a *Auth) {
	if !IsCodexOAuthLikeAuth(a) {
		return
	}
	a.ensureMetadata()
	if authPreferredInterval(a) <= 0 {
		a.Metadata[CodexQuotaRefreshIntervalSecondsKey] = int(CodexQuotaRefreshInterval / time.Second)
	}
}

func ApplyCodexQuotaBlockedUntil(a *Auth, blockedUntil *time.Time) {
	if a == nil || !strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
		return
	}
	if blockedUntil != nil && !blockedUntil.IsZero() {
		until := blockedUntil.UTC()
		a.Unavailable = true
		a.NextRetryAfter = until
		a.Quota.Exceeded = true
		a.Quota.Reason = "quota"
		a.Quota.NextRecoverAt = until
		return
	}
	shouldClearCooldown := a.Quota.Exceeded || strings.EqualFold(strings.TrimSpace(a.Quota.Reason), "quota") || !a.Quota.NextRecoverAt.IsZero()
	if shouldClearCooldown {
		a.Quota.Exceeded = false
		a.Quota.Reason = ""
		a.Quota.NextRecoverAt = time.Time{}
		a.Quota.BackoffLevel = 0
	}
	if shouldClearCooldown && a.Unavailable && !a.NextRetryAfter.IsZero() {
		a.Unavailable = false
		a.NextRetryAfter = time.Time{}
	}
}

func (a *Auth) ensureMetadata() {
	if a != nil && a.Metadata == nil {
		a.Metadata = map[string]any{}
	}
}

func (a *Auth) readCodexFloat(key string) (float64, bool) {
	if a == nil || a.Metadata == nil {
		return 0, false
	}
	parsed, ok := parseFloatAny(a.Metadata[key])
	if !ok {
		delete(a.Metadata, key)
		return 0, false
	}
	a.Metadata[key] = parsed
	return parsed, true
}

func (a *Auth) writeCodexFloat(key string, value float64) {
	if a == nil {
		return
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	a.ensureMetadata()
	a.Metadata[key] = value
}

func (a *Auth) readCodexString(key string) string {
	if a == nil || a.Metadata == nil {
		return ""
	}
	val, _ := a.Metadata[key].(string)
	return strings.TrimSpace(val)
}

func (a *Auth) writeCodexString(key, value string) {
	if a == nil {
		return
	}
	trimmed := strings.TrimSpace(value)
	a.ensureMetadata()
	if trimmed == "" {
		delete(a.Metadata, key)
		return
	}
	a.Metadata[key] = trimmed
}

func codexQuotaStateFromAny(raw any) (CodexQuotaState, bool) {
	switch typed := raw.(type) {
	case nil:
		return CodexQuotaState{}, false
	case CodexQuotaState:
		return typed, typed.hasData()
	case *CodexQuotaState:
		if typed == nil {
			return CodexQuotaState{}, false
		}
		return *typed, typed.hasData()
	case map[string]any:
		return codexQuotaStateFromMap(typed)
	case map[string]string:
		converted := make(map[string]any, len(typed))
		for k, v := range typed {
			converted[k] = v
		}
		return codexQuotaStateFromMap(converted)
	default:
		return CodexQuotaState{}, false
	}
}

func codexQuotaStateFromMap(raw map[string]any) (CodexQuotaState, bool) {
	if raw == nil {
		return CodexQuotaState{}, false
	}
	var state CodexQuotaState
	state.FiveHour = codexQuotaBucketFromAny(raw["five_hour"])
	state.Weekly = codexQuotaBucketFromAny(raw["weekly"])
	if ts, ok := parseTimeValue(raw["last_refresh_at"]); ok && !ts.IsZero() {
		state.LastRefreshAt = &ts
	}
	if status, ok := raw["refresh_status"].(string); ok {
		state.RefreshStatus = strings.TrimSpace(status)
	}
	if refreshErr, ok := raw["refresh_error"].(string); ok {
		state.RefreshError = strings.TrimSpace(refreshErr)
	}
	return state, state.hasData()
}

func codexQuotaBucketFromAny(raw any) CodexQuotaBucket {
	switch typed := raw.(type) {
	case CodexQuotaBucket:
		return typed
	case *CodexQuotaBucket:
		if typed == nil {
			return CodexQuotaBucket{}
		}
		return *typed
	case map[string]any:
		return codexQuotaBucketFromMap(typed)
	case map[string]string:
		converted := make(map[string]any, len(typed))
		for k, v := range typed {
			converted[k] = v
		}
		return codexQuotaBucketFromMap(converted)
	default:
		return CodexQuotaBucket{}
	}
}

func codexQuotaBucketFromMap(raw map[string]any) CodexQuotaBucket {
	var bucket CodexQuotaBucket
	if raw == nil {
		return bucket
	}
	if remaining, ok := parseFloatAny(raw["remaining"]); ok {
		bucket.Remaining = float64Ptr(remaining)
	}
	if limit, ok := parseFloatAny(raw["limit"]); ok {
		bucket.Limit = float64Ptr(limit)
	}
	if ts, ok := parseTimeValue(raw["reset_at"]); ok && !ts.IsZero() {
		bucket.ResetAt = &ts
	}
	return bucket
}

func (s CodexQuotaState) hasData() bool {
	return s.FiveHour.hasData() || s.Weekly.hasData() || s.LastRefreshAt != nil || s.RefreshStatus != "" || s.RefreshError != ""
}

func (b CodexQuotaBucket) hasData() bool {
	return b.Remaining != nil || b.Limit != nil || b.ResetAt != nil
}

func (s CodexQuotaState) metadataValue() any {
	if !s.hasData() {
		return nil
	}
	out := map[string]any{}
	if bucket := s.FiveHour.metadataValue(); bucket != nil {
		out["five_hour"] = bucket
	}
	if bucket := s.Weekly.metadataValue(); bucket != nil {
		out["weekly"] = bucket
	}
	if s.LastRefreshAt != nil && !s.LastRefreshAt.IsZero() {
		out["last_refresh_at"] = s.LastRefreshAt.UTC().Format(time.RFC3339)
	}
	if trimmed := strings.TrimSpace(s.RefreshStatus); trimmed != "" {
		out["refresh_status"] = trimmed
	}
	if trimmed := strings.TrimSpace(s.RefreshError); trimmed != "" {
		out["refresh_error"] = trimmed
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (b CodexQuotaBucket) metadataValue() map[string]any {
	out := map[string]any{}
	if b.Remaining != nil {
		out["remaining"] = *b.Remaining
	}
	if b.Limit != nil {
		out["limit"] = *b.Limit
	}
	if b.ResetAt != nil && !b.ResetAt.IsZero() {
		out["reset_at"] = b.ResetAt.UTC().Format(time.RFC3339)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseFloatAny(val any) (float64, bool) {
	switch typed := val.(type) {
	case float64:
		return sanitizeFiniteFloat(typed)
	case float32:
		return sanitizeFiniteFloat(float64(typed))
	case int:
		return float64(typed), true
	case int32:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		return sanitizeFiniteFloat(parsed)
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, false
		}
		return sanitizeFiniteFloat(parsed)
	default:
		return 0, false
	}
}

func sanitizeFiniteFloat(v float64) (float64, bool) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

func float64Ptr(v float64) *float64 {
	return &v
}
