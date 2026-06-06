package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/codex"
	internalcache "github.com/router-for-me/CLIProxyAPI/v7/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/signature"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"github.com/tiktoken-go/tokenizer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	codexUserAgent             = "codex-tui/0.135.0 (Mac OS 26.5.0; arm64) iTerm.app/3.6.10 (codex-tui; 0.135.0)"
	codexQuotaRefreshUserAgent = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"
	codexOriginator            = "codex-tui"
	codexDefaultImageToolModel = "gpt-image-2"
)

var dataTag = []byte("data:")
var codexClaudeCodeSessionPattern = regexp.MustCompile(`_session_([a-f0-9-]+)$`)

// Streamed Codex responses may emit response.output_item.done events while leaving
// response.completed.response.output empty. Keep the stream path aligned with the
// already-patched non-stream path by reconstructing response.output from those items.
func collectCodexOutputItemDone(eventData []byte, outputItemsByIndex map[int64][]byte, outputItemsFallback *[][]byte) {
	itemResult := gjson.GetBytes(eventData, "item")
	if !itemResult.Exists() || itemResult.Type != gjson.JSON {
		return
	}
	outputIndexResult := gjson.GetBytes(eventData, "output_index")
	if outputIndexResult.Exists() {
		outputItemsByIndex[outputIndexResult.Int()] = []byte(itemResult.Raw)
		return
	}
	*outputItemsFallback = append(*outputItemsFallback, []byte(itemResult.Raw))
}

func patchCodexCompletedOutput(eventData []byte, outputItemsByIndex map[int64][]byte, outputItemsFallback [][]byte) []byte {
	outputResult := gjson.GetBytes(eventData, "response.output")
	shouldPatchOutput := (!outputResult.Exists() || !outputResult.IsArray() || len(outputResult.Array()) == 0) && (len(outputItemsByIndex) > 0 || len(outputItemsFallback) > 0)
	if !shouldPatchOutput {
		return eventData
	}

	indexes := make([]int64, 0, len(outputItemsByIndex))
	for idx := range outputItemsByIndex {
		indexes = append(indexes, idx)
	}
	sort.Slice(indexes, func(i, j int) bool {
		return indexes[i] < indexes[j]
	})

	items := make([][]byte, 0, len(outputItemsByIndex)+len(outputItemsFallback))
	for _, idx := range indexes {
		items = append(items, outputItemsByIndex[idx])
	}
	items = append(items, outputItemsFallback...)

	outputArray := []byte("[]")
	if len(items) > 0 {
		var buf bytes.Buffer
		totalLen := 2
		for _, item := range items {
			totalLen += len(item)
		}
		if len(items) > 1 {
			totalLen += len(items) - 1
		}
		buf.Grow(totalLen)
		buf.WriteByte('[')
		for i, item := range items {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.Write(item)
		}
		buf.WriteByte(']')
		outputArray = buf.Bytes()
	}

	completedDataPatched, _ := sjson.SetRawBytes(eventData, "response.output", outputArray)
	return completedDataPatched
}

func codexTerminalStreamContextLengthErr(eventData []byte) (statusErr, bool) {
	streamErr, body, ok := codexTerminalStreamErr(eventData)
	if !ok || !codexTerminalErrorIsContextLength(body) {
		return statusErr{}, false
	}
	return streamErr, true
}

func codexTerminalStreamErr(eventData []byte) (statusErr, []byte, bool) {
	eventType := gjson.GetBytes(eventData, "type").String()
	var body []byte
	switch eventType {
	case "error":
		body = codexTerminalErrorBody(eventData, "error")
		if len(body) == 0 {
			body = codexTerminalTopLevelErrorBody(eventData)
		}
	case "response.failed":
		body = codexTerminalErrorBody(eventData, "response.error")
		if len(body) == 0 {
			body = codexTerminalErrorBody(eventData, "error")
		}
	default:
		return statusErr{}, nil, false
	}
	if len(body) == 0 {
		return statusErr{}, nil, false
	}
	if !codexTerminalStreamErrShouldHandle(body) {
		return statusErr{}, nil, false
	}
	return newCodexStatusErr(http.StatusBadRequest, body), body, true
}

func codexTerminalStreamErrShouldHandle(body []byte) bool {
	if codexTerminalErrorIsContextLength(body) {
		return true
	}
	code, _, ok := codexStatusErrorClassification(http.StatusBadRequest, body)
	return ok && code == "thinking_signature_invalid"
}

func codexTerminalErrorBody(eventData []byte, path string) []byte {
	errorResult := gjson.GetBytes(eventData, path)
	if !errorResult.Exists() {
		return nil
	}
	body := []byte(`{"error":{}}`)
	if errorResult.Type == gjson.JSON {
		body, _ = sjson.SetRawBytes(body, "error", []byte(errorResult.Raw))
	} else if message := strings.TrimSpace(errorResult.String()); message != "" {
		body, _ = sjson.SetBytes(body, "error.message", message)
	}
	if strings.TrimSpace(gjson.GetBytes(body, "error.message").String()) == "" {
		if message := strings.TrimSpace(gjson.GetBytes(eventData, "response.error.message").String()); message != "" {
			body, _ = sjson.SetBytes(body, "error.message", message)
		}
	}
	if strings.TrimSpace(gjson.GetBytes(body, "error.message").String()) == "" {
		if code := strings.TrimSpace(gjson.GetBytes(body, "error.code").String()); code != "" {
			body, _ = sjson.SetBytes(body, "error.message", code)
		}
	}
	if strings.TrimSpace(gjson.GetBytes(body, "error.message").String()) == "" {
		if errorType := strings.TrimSpace(gjson.GetBytes(body, "error.type").String()); errorType != "" {
			body, _ = sjson.SetBytes(body, "error.message", errorType)
		}
	}
	return body
}

func codexTerminalTopLevelErrorBody(eventData []byte) []byte {
	message := strings.TrimSpace(gjson.GetBytes(eventData, "message").String())
	code := strings.TrimSpace(gjson.GetBytes(eventData, "code").String())
	errorType := strings.TrimSpace(gjson.GetBytes(eventData, "error_type").String())
	param := strings.TrimSpace(gjson.GetBytes(eventData, "param").String())
	if message == "" && code == "" && errorType == "" && param == "" {
		return nil
	}

	body := []byte(`{"error":{}}`)
	if message != "" {
		body, _ = sjson.SetBytes(body, "error.message", message)
	}
	if code != "" {
		body, _ = sjson.SetBytes(body, "error.code", code)
	}
	if errorType != "" {
		body, _ = sjson.SetBytes(body, "error.type", errorType)
	}
	if param != "" {
		body, _ = sjson.SetBytes(body, "error.param", param)
	}
	if strings.TrimSpace(gjson.GetBytes(body, "error.message").String()) == "" {
		if code != "" {
			body, _ = sjson.SetBytes(body, "error.message", code)
		} else if errorType != "" {
			body, _ = sjson.SetBytes(body, "error.message", errorType)
		}
	}
	return body
}

func codexTerminalErrorIsContextLength(body []byte) bool {
	errorCode := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.code").String()))
	message := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.message").String()))
	return errorCode == "context_length_exceeded" ||
		errorCode == "context_too_large" ||
		strings.Contains(message, "context window") ||
		strings.Contains(message, "context length") ||
		strings.Contains(message, "too many tokens")
}

// CodexExecutor is a stateless executor for Codex (OpenAI Responses API entrypoint).
// If api_key is unavailable on auth, it falls back to legacy via ClientAdapter.
type CodexExecutor struct {
	cfg *config.Config
}

func NewCodexExecutor(cfg *config.Config) *CodexExecutor { return &CodexExecutor{cfg: cfg} }

func (e *CodexExecutor) Identifier() string { return "codex" }

func translateCodexRequestPair(from, to sdktranslator.Format, model string, originalPayload, payload []byte, stream bool) ([]byte, []byte) {
	if bytes.Equal(originalPayload, payload) {
		body := sdktranslator.TranslateRequest(from, to, model, payload, stream)
		return body, body
	}
	originalTranslated := sdktranslator.TranslateRequest(from, to, model, originalPayload, stream)
	body := sdktranslator.TranslateRequest(from, to, model, payload, stream)
	return originalTranslated, body
}

type codexReasoningReplayScope struct {
	modelName  string
	sessionKey string
}

func (s codexReasoningReplayScope) valid() bool {
	return strings.TrimSpace(s.modelName) != "" && strings.TrimSpace(s.sessionKey) != ""
}

func applyCodexReasoningReplayCache(ctx context.Context, from sdktranslator.Format, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, body []byte) ([]byte, codexReasoningReplayScope) {
	scope := codexReasoningReplayScopeFromRequest(ctx, from, req, opts, body)
	if !scope.valid() {
		return body, scope
	}
	items, ok := internalcache.GetCodexReasoningReplayItems(scope.modelName, scope.sessionKey)
	if !ok {
		return body, scope
	}
	items = filterCodexReasoningReplayItemsForInput(body, items)
	if len(items) == 0 {
		return body, scope
	}
	updated, ok := insertCodexReasoningReplayItems(body, items)
	if !ok {
		return body, scope
	}
	return updated, scope
}

func codexReasoningReplayScopeFromRequest(ctx context.Context, from sdktranslator.Format, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, body []byte) codexReasoningReplayScope {
	if !codexReasoningReplayEnabledForSource(from) {
		return codexReasoningReplayScope{}
	}
	return codexReasoningReplayScope{
		modelName:  thinking.ParseSuffix(req.Model).ModelName,
		sessionKey: codexReasoningReplaySessionKey(ctx, from, req, opts, body),
	}
}

func codexReasoningReplayEnabledForSource(from sdktranslator.Format) bool {
	return sourceFormatEqual(from, sdktranslator.FormatClaude)
}

func sourceFormatEqual(from, want sdktranslator.Format) bool {
	return strings.EqualFold(strings.TrimSpace(from.String()), want.String())
}

func codexClaudeCodeReplaySessionKey(payload []byte) string {
	sessionID := extractClaudeCodeSessionIDForCodexReplay(payload)
	if sessionID == "" {
		return ""
	}
	return "claude:" + sessionID
}

func codexClaudeCodePromptCacheStorageKey(req cliproxyexecutor.Request) string {
	sessionID := extractClaudeCodeSessionIDForCodexReplay(req.Payload)
	if sessionID == "" {
		return ""
	}
	return fmt.Sprintf("%s-claude:%s", req.Model, sessionID)
}

func codexClaudeCodePromptCache(req cliproxyexecutor.Request) (helps.CodexCache, bool) {
	key := codexClaudeCodePromptCacheStorageKey(req)
	if key == "" {
		return helps.CodexCache{}, false
	}
	if cache, ok := helps.GetCodexCache(key); ok {
		return cache, true
	}
	cache := helps.CodexCache{
		ID:     uuid.New().String(),
		Expire: time.Now().Add(1 * time.Hour),
	}
	helps.SetCodexCache(key, cache)
	return cache, true
}

func extractClaudeCodeSessionIDForCodexReplay(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	userID := gjson.GetBytes(payload, "metadata.user_id").String()
	if userID == "" {
		return ""
	}
	if matches := codexClaudeCodeSessionPattern.FindStringSubmatch(userID); len(matches) >= 2 {
		return matches[1]
	}
	if len(userID) > 0 && userID[0] == '{' {
		return gjson.Get(userID, "session_id").String()
	}
	return ""
}

func codexReasoningReplaySessionKey(ctx context.Context, from sdktranslator.Format, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, body []byte) string {
	if ctx == nil {
		ctx = context.Background()
	}
	if value := metadataString(opts.Metadata, cliproxyexecutor.ExecutionSessionMetadataKey); value != "" {
		return "execution:" + value
	}
	if value := metadataString(req.Metadata, cliproxyexecutor.ExecutionSessionMetadataKey); value != "" {
		return "execution:" + value
	}
	if value := codexReasoningReplaySessionKeyFromPayload(body); value != "" {
		return value
	}
	if value := codexReasoningReplaySessionKeyFromPayload(req.Payload); value != "" {
		return value
	}
	if value := codexReasoningReplaySessionKeyFromHeaders(opts.Headers); value != "" {
		return value
	}
	if ginCtx, ok := ctx.Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		if value := codexReasoningReplaySessionKeyFromHeaders(ginCtx.Request.Header); value != "" {
			return value
		}
	}
	if sourceFormatEqual(from, sdktranslator.FormatClaude) {
		return codexClaudeCodeReplaySessionKey(req.Payload)
	}
	if sourceFormatEqual(from, sdktranslator.FormatOpenAI) {
		if apiKey := strings.TrimSpace(helps.APIKeyFromContext(ctx)); apiKey != "" {
			return "prompt-cache:" + uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache:"+apiKey)).String()
		}
	}
	return ""
}

func metadataString(metadata map[string]any, key string) string {
	if len(metadata) == 0 {
		return ""
	}
	raw, ok := metadata[key]
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case []byte:
		return strings.TrimSpace(string(v))
	default:
		return ""
	}
}

func codexReasoningReplaySessionKeyFromPayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	if promptCacheKey := strings.TrimSpace(gjson.GetBytes(payload, "prompt_cache_key").String()); promptCacheKey != "" {
		return "prompt-cache:" + promptCacheKey
	}
	if windowID := strings.TrimSpace(gjson.GetBytes(payload, "client_metadata.x-codex-window-id").String()); windowID != "" {
		return "window:" + windowID
	}
	if turnMetadata := strings.TrimSpace(gjson.GetBytes(payload, "client_metadata.x-codex-turn-metadata").String()); turnMetadata != "" {
		return codexReasoningReplaySessionKeyFromTurnMetadata(turnMetadata)
	}
	return ""
}

func codexReasoningReplaySessionKeyFromHeaders(headers http.Header) string {
	if headers == nil {
		return ""
	}
	if turnMetadata := strings.TrimSpace(headers.Get("X-Codex-Turn-Metadata")); turnMetadata != "" {
		if key := codexReasoningReplaySessionKeyFromTurnMetadata(turnMetadata); key != "" {
			return key
		}
	}
	if windowID := strings.TrimSpace(headerValueCaseInsensitive(headers, "X-Codex-Window-Id")); windowID != "" {
		return "window:" + windowID
	}
	for _, headerName := range []string{"Session_id", "session_id", "Session-Id"} {
		if value := strings.TrimSpace(headerValueCaseInsensitive(headers, headerName)); value != "" {
			return "session-id:" + value
		}
	}
	if conversationID := strings.TrimSpace(headerValueCaseInsensitive(headers, "Conversation_id")); conversationID != "" {
		return "conversation_id:" + conversationID
	}
	return ""
}

func codexReasoningReplaySessionKeyFromTurnMetadata(turnMetadata string) string {
	if promptCacheKey := strings.TrimSpace(gjson.Get(turnMetadata, "prompt_cache_key").String()); promptCacheKey != "" {
		return "prompt-cache:" + promptCacheKey
	}
	if windowID := strings.TrimSpace(gjson.Get(turnMetadata, "window_id").String()); windowID != "" {
		return "window:" + windowID
	}
	return ""
}

func codexInputHasValidReasoningEncryptedContent(body []byte) bool {
	input := gjson.GetBytes(body, "input")
	if !input.IsArray() {
		return false
	}
	for _, item := range input.Array() {
		if strings.TrimSpace(item.Get("type").String()) != "reasoning" {
			continue
		}
		encryptedContent := item.Get("encrypted_content")
		if encryptedContent.Type != gjson.String {
			continue
		}
		if _, err := signature.InspectGPTReasoningSignature(encryptedContent.String()); err == nil {
			return true
		}
	}
	return false
}

func filterCodexReasoningReplayItemsForInput(body []byte, items [][]byte) [][]byte {
	input := gjson.GetBytes(body, "input")
	if !input.IsArray() {
		return nil
	}

	hasInputReasoning := codexInputHasValidReasoningEncryptedContent(body)
	existingCalls := make(map[string]bool)
	existingOutputs := make(map[string]bool)
	for _, inputItem := range input.Array() {
		itemType := strings.TrimSpace(inputItem.Get("type").String())
		if itemType == "function_call_output" || itemType == "custom_tool_call_output" {
			callID := strings.TrimSpace(inputItem.Get("call_id").String())
			if callID != "" {
				for _, candidate := range codexReplayComparableCallIDs(callID) {
					existingOutputs[candidate] = true
				}
			}
		}
		for _, key := range codexReplayToolCallKeys(inputItem) {
			existingCalls[key] = true
		}
	}

	filtered := make([][]byte, 0, len(items))
	for _, item := range items {
		itemResult := gjson.ParseBytes(item)
		switch strings.TrimSpace(itemResult.Get("type").String()) {
		case "reasoning":
			if hasInputReasoning {
				continue
			}
		case "function_call", "custom_tool_call":
			keys := codexReplayToolCallKeys(itemResult)
			if len(keys) == 0 || codexReplayAnyToolCallKeyExists(existingCalls, keys) {
				continue
			}
			// Only inject if there is a matching output in the request
			hasMatchingOutput := false
			callID := strings.TrimSpace(itemResult.Get("call_id").String())
			if callID != "" {
				for _, candidate := range codexReplayComparableCallIDs(callID) {
					if existingOutputs[candidate] {
						hasMatchingOutput = true
						break
					}
				}
			}
			if !hasMatchingOutput {
				continue
			}
			for _, key := range keys {
				existingCalls[key] = true
			}
		default:
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func insertCodexReasoningReplayItems(body []byte, replayItems [][]byte) ([]byte, bool) {
	input := gjson.GetBytes(body, "input")
	if !input.IsArray() || len(replayItems) == 0 {
		return body, false
	}
	inputItems := input.Array()
	insertIndex := codexReasoningReplayInsertIndex(inputItems, replayItems)
	replayItems = codexAlignReasoningReplayToolCallIDs(inputItems, replayItems)
	items := make([]string, 0, len(inputItems)+len(replayItems))
	for i, inputItem := range inputItems {
		if i == insertIndex {
			for _, replayItem := range replayItems {
				items = append(items, string(replayItem))
			}
		}
		items = append(items, inputItem.Raw)
	}
	if insertIndex == len(inputItems) {
		for _, replayItem := range replayItems {
			items = append(items, string(replayItem))
		}
	}
	updated, err := sjson.SetRawBytes(body, "input", []byte("["+strings.Join(items, ",")+"]"))
	if err != nil {
		return body, false
	}
	return updated, true
}

func codexReasoningReplayInsertIndex(inputItems []gjson.Result, replayItems [][]byte) int {
	replayCallIDs := make(map[string]bool)
	for _, replayItem := range replayItems {
		itemResult := gjson.ParseBytes(replayItem)
		itemType := strings.TrimSpace(itemResult.Get("type").String())
		if itemType != "function_call" && itemType != "custom_tool_call" {
			continue
		}
		for _, callID := range codexReplayComparableCallIDs(itemResult.Get("call_id").String()) {
			replayCallIDs[callID] = true
		}
	}
	if len(replayCallIDs) > 0 {
		for index, inputItem := range inputItems {
			itemType := strings.TrimSpace(inputItem.Get("type").String())
			if itemType != "function_call_output" && itemType != "custom_tool_call_output" {
				continue
			}
			callID := strings.TrimSpace(inputItem.Get("call_id").String())
			if callID == "" || replayCallIDs[callID] {
				return index
			}
		}
	}
	for index := len(inputItems) - 1; index >= 0; index-- {
		inputItem := inputItems[index]
		if strings.TrimSpace(inputItem.Get("type").String()) == "message" && strings.TrimSpace(inputItem.Get("role").String()) == "assistant" {
			return index
		}
	}
	for index, inputItem := range inputItems {
		if shouldInsertCodexReasoningReplayBefore(inputItem) {
			return index
		}
	}
	return len(inputItems)
}

func codexAlignReasoningReplayToolCallIDs(inputItems []gjson.Result, replayItems [][]byte) [][]byte {
	outputCallIDs := codexReplayOutputCallIDs(inputItems)
	if len(outputCallIDs) == 0 {
		return replayItems
	}

	aligned := make([][]byte, 0, len(replayItems))
	for _, replayItem := range replayItems {
		itemResult := gjson.ParseBytes(replayItem)
		itemType := strings.TrimSpace(itemResult.Get("type").String())
		if itemType != "function_call" && itemType != "custom_tool_call" {
			aligned = append(aligned, replayItem)
			continue
		}

		callID := strings.TrimSpace(itemResult.Get("call_id").String())
		outputCallID := ""
		for _, candidate := range codexReplayComparableCallIDs(callID) {
			if value := outputCallIDs[candidate]; value != "" {
				outputCallID = value
				break
			}
		}
		if outputCallID == "" || outputCallID == callID {
			aligned = append(aligned, replayItem)
			continue
		}

		updated, err := sjson.SetBytes(replayItem, "call_id", outputCallID)
		if err != nil {
			aligned = append(aligned, replayItem)
			continue
		}
		aligned = append(aligned, updated)
	}
	return aligned
}

func codexReplayOutputCallIDs(inputItems []gjson.Result) map[string]string {
	outputCallIDs := make(map[string]string)
	for _, inputItem := range inputItems {
		itemType := strings.TrimSpace(inputItem.Get("type").String())
		if itemType != "function_call_output" && itemType != "custom_tool_call_output" {
			continue
		}
		callID := strings.TrimSpace(inputItem.Get("call_id").String())
		if callID == "" {
			continue
		}
		for _, candidate := range codexReplayComparableCallIDs(callID) {
			outputCallIDs[candidate] = callID
		}
	}
	return outputCallIDs
}

func shouldInsertCodexReasoningReplayBefore(item gjson.Result) bool {
	if strings.TrimSpace(item.Get("type").String()) != "message" {
		return true
	}
	switch strings.TrimSpace(item.Get("role").String()) {
	case "developer", "system":
		return false
	default:
		return true
	}
}

func codexReplayToolCallKeys(item gjson.Result) []string {
	itemType := strings.TrimSpace(item.Get("type").String())
	if itemType != "function_call" && itemType != "custom_tool_call" {
		return nil
	}
	callIDs := codexReplayComparableCallIDs(item.Get("call_id").String())
	if len(callIDs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(callIDs))
	for _, callID := range callIDs {
		keys = append(keys, itemType+":"+callID)
	}
	return keys
}

func codexReplayAnyToolCallKeyExists(existing map[string]bool, keys []string) bool {
	for _, key := range keys {
		if existing[key] {
			return true
		}
	}
	return false
}

func codexReplayComparableCallIDs(callID string) []string {
	callID = strings.TrimSpace(callID)
	if callID == "" {
		return nil
	}

	claudeVisibleCallID := shortenCodexReplayCallIDIfNeeded(util.SanitizeClaudeToolID(callID))
	if claudeVisibleCallID == "" || claudeVisibleCallID == callID {
		return []string{callID}
	}
	return []string{callID, claudeVisibleCallID}
}

func shortenCodexReplayCallIDIfNeeded(id string) string {
	const limit = 64
	if len(id) <= limit {
		return id
	}

	sum := sha256.Sum256([]byte(id))
	suffix := "_" + hex.EncodeToString(sum[:8])
	prefixLen := limit - len(suffix)
	if prefixLen <= 0 {
		return suffix[len(suffix)-limit:]
	}
	return id[:prefixLen] + suffix
}

func cacheCodexReasoningReplayFromCompleted(scope codexReasoningReplayScope, completedData []byte) {
	if !scope.valid() {
		return
	}
	output := gjson.GetBytes(completedData, "response.output")
	if !output.IsArray() {
		return
	}
	items := make([][]byte, 0, len(output.Array()))
	for _, item := range output.Array() {
		switch strings.TrimSpace(item.Get("type").String()) {
		case "reasoning", "function_call", "custom_tool_call":
			items = append(items, []byte(item.Raw))
		default:
			continue
		}
	}
	if !internalcache.CacheCodexReasoningReplayItems(scope.modelName, scope.sessionKey, items) {
		internalcache.DeleteCodexReasoningReplayItem(scope.modelName, scope.sessionKey)
	}
}

func clearCodexReasoningReplayOnInvalidSignature(scope codexReasoningReplayScope, statusCode int, body []byte) {
	if !scope.valid() {
		return
	}
	code, _, ok := codexStatusErrorClassification(statusCode, body)
	if ok && code == "thinking_signature_invalid" {
		internalcache.DeleteCodexReasoningReplayItem(scope.modelName, scope.sessionKey)
	}
}

// PrepareRequest injects Codex credentials into the outgoing HTTP request.
func (e *CodexExecutor) PrepareRequest(req *http.Request, auth *cliproxyauth.Auth) error {
	if req == nil {
		return nil
	}
	apiKey, _ := codexCreds(auth)
	if strings.TrimSpace(apiKey) != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(req, attrs)
	return nil
}

// HttpRequest injects Codex credentials into the request and executes it.
func (e *CodexExecutor) HttpRequest(ctx context.Context, auth *cliproxyauth.Auth, req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("codex executor: request is nil")
	}
	if ctx == nil {
		ctx = req.Context()
	}
	httpReq := req.WithContext(ctx)
	if err := e.PrepareRequest(httpReq, auth); err != nil {
		return nil, err
	}
	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	return httpClient.Do(httpReq)
}

func (e *CodexExecutor) Execute(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	if opts.Alt == "responses/compact" {
		return e.executeCompact(ctx, auth, req, opts)
	}
	if isCodexOpenAIImageRequest(opts) {
		return e.executeOpenAIImage(ctx, auth, req, opts)
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	apiKey, baseURL := codexCreds(auth)
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FromString("codex")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated, body := translateCodexRequestPair(from, to, baseModel, originalPayload, req.Payload, false)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return resp, err
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)
	body, _ = sjson.SetBytes(body, "model", baseModel)
	body, _ = sjson.SetBytes(body, "stream", true)
	body, _ = sjson.DeleteBytes(body, "previous_response_id")
	body, _ = sjson.DeleteBytes(body, "prompt_cache_retention")
	body, _ = sjson.DeleteBytes(body, "safety_identifier")
	body, _ = sjson.DeleteBytes(body, "stream_options")
	body = normalizeCodexInstructions(body)
	if e.cfg == nil || e.cfg.DisableImageGeneration == config.DisableImageGenerationOff {
		body = ensureImageGenerationTool(body, baseModel, auth)
	}
	body = sanitizeOpenAIResponsesReasoningEncryptedContent(ctx, "codex executor", body)
	body, replayScope := applyCodexReasoningReplayCache(ctx, from, req, opts, body)
	reporter.SetTranslatedReasoningEffort(body, to.String())

	url := strings.TrimSuffix(baseURL, "/") + "/responses"
	var identityState codexIdentityConfuseState
	httpReq, upstreamBody, identityState, err := e.cacheHelper(ctx, from, url, auth, req, originalPayloadSource, body)
	if err != nil {
		return resp, err
	}
	applyCodexHeaders(httpReq, auth, apiKey, true, e.cfg)
	applyCodexIdentityConfuseHeaders(httpReq.Header, &identityState)
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      upstreamBody,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})
	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("codex executor: close response body error: %v", errClose)
		}
	}()
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		b = applyCodexIdentityConfuseResponsePayload(b, identityState)
		clearCodexReasoningReplayOnInvalidSignature(replayScope, httpResp.StatusCode, b)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = newCodexStatusErr(httpResp.StatusCode, b)
		return resp, err
	}
	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	upstreamData := applyCodexIdentityConfuseResponsePayload(data, identityState)
	helps.AppendAPIResponseChunk(ctx, e.cfg, upstreamData)

	lines := bytes.Split(upstreamData, []byte("\n"))
	outputItemsByIndex := make(map[int64][]byte)
	var outputItemsFallback [][]byte
	for _, line := range lines {
		if !bytes.HasPrefix(line, dataTag) {
			continue
		}

		eventData := bytes.TrimSpace(line[5:])
		eventType := gjson.GetBytes(eventData, "type").String()

		if streamErr, terminalBody, ok := codexTerminalStreamErr(eventData); ok {
			clearCodexReasoningReplayOnInvalidSignature(replayScope, streamErr.StatusCode(), terminalBody)
			err = streamErr
			return resp, err
		}

		if eventType == "response.output_item.done" {
			itemResult := gjson.GetBytes(eventData, "item")
			if !itemResult.Exists() || itemResult.Type != gjson.JSON {
				continue
			}
			outputIndexResult := gjson.GetBytes(eventData, "output_index")
			if outputIndexResult.Exists() {
				outputItemsByIndex[outputIndexResult.Int()] = []byte(itemResult.Raw)
			} else {
				outputItemsFallback = append(outputItemsFallback, []byte(itemResult.Raw))
			}
			continue
		}

		if eventType != "response.completed" {
			continue
		}

		if detail, ok := helps.ParseCodexUsage(eventData); ok {
			reporter.Publish(ctx, detail)
		}
		publishCodexImageToolUsage(ctx, reporter, body, eventData)

		completedData := eventData
		outputResult := gjson.GetBytes(completedData, "response.output")
		shouldPatchOutput := (!outputResult.Exists() || !outputResult.IsArray() || len(outputResult.Array()) == 0) && (len(outputItemsByIndex) > 0 || len(outputItemsFallback) > 0)
		if shouldPatchOutput {
			completedDataPatched := completedData
			completedDataPatched, _ = sjson.SetRawBytes(completedDataPatched, "response.output", []byte(`[]`))

			indexes := make([]int64, 0, len(outputItemsByIndex))
			for idx := range outputItemsByIndex {
				indexes = append(indexes, idx)
			}
			sort.Slice(indexes, func(i, j int) bool {
				return indexes[i] < indexes[j]
			})
			for _, idx := range indexes {
				completedDataPatched, _ = sjson.SetRawBytes(completedDataPatched, "response.output.-1", outputItemsByIndex[idx])
			}
			for _, item := range outputItemsFallback {
				completedDataPatched, _ = sjson.SetRawBytes(completedDataPatched, "response.output.-1", item)
			}
			completedData = completedDataPatched
		}
		cacheCodexReasoningReplayFromCompleted(replayScope, completedData)

		var param any
		clientCompletedData := applyCodexIdentityExposeResponsePayload(completedData, identityState)
		out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, originalPayload, body, clientCompletedData, &param)
		resp = cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}
		return resp, nil
	}
	err = statusErr{code: 408, msg: "stream error: stream disconnected before completion: stream closed before response.completed"}
	return resp, err
}

func (e *CodexExecutor) executeCompact(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (resp cliproxyexecutor.Response, err error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	apiKey, baseURL := codexCreds(auth)
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FromString("openai-response")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated, body := translateCodexRequestPair(from, to, baseModel, originalPayload, req.Payload, false)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return resp, err
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)
	body, _ = sjson.SetBytes(body, "model", baseModel)
	body, _ = sjson.DeleteBytes(body, "stream")
	body = normalizeCodexInstructions(body)
	if e.cfg == nil || e.cfg.DisableImageGeneration == config.DisableImageGenerationOff {
		body = ensureImageGenerationTool(body, baseModel, auth)
	}
	body = sanitizeOpenAIResponsesReasoningEncryptedContent(ctx, "codex executor", body)
	reporter.SetTranslatedReasoningEffort(body, to.String())

	url := strings.TrimSuffix(baseURL, "/") + "/responses/compact"
	var identityState codexIdentityConfuseState
	httpReq, upstreamBody, identityState, err := e.cacheHelper(ctx, from, url, auth, req, originalPayloadSource, body)
	if err != nil {
		return resp, err
	}
	applyCodexHeaders(httpReq, auth, apiKey, false, e.cfg)
	applyCodexIdentityConfuseHeaders(httpReq.Header, &identityState)
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      upstreamBody,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})
	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	defer func() {
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("codex executor: close response body error: %v", errClose)
		}
	}()
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		b = applyCodexIdentityConfuseResponsePayload(b, identityState)
		helps.AppendAPIResponseChunk(ctx, e.cfg, b)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), b))
		err = newCodexStatusErr(httpResp.StatusCode, b)
		return resp, err
	}
	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return resp, err
	}
	upstreamData := applyCodexIdentityConfuseResponsePayload(data, identityState)
	helps.AppendAPIResponseChunk(ctx, e.cfg, upstreamData)
	reporter.Publish(ctx, helps.ParseOpenAIUsage(upstreamData))
	reporter.EnsurePublished(ctx)
	var param any
	clientData := applyCodexIdentityExposeResponsePayload(upstreamData, identityState)
	out := sdktranslator.TranslateNonStream(ctx, to, from, req.Model, originalPayload, body, clientData, &param)
	resp = cliproxyexecutor.Response{Payload: out, Headers: httpResp.Header.Clone()}
	return resp, nil
}

func (e *CodexExecutor) ExecuteStream(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (_ *cliproxyexecutor.StreamResult, err error) {
	if opts.Alt == "responses/compact" {
		return nil, statusErr{code: http.StatusBadRequest, msg: "streaming not supported for /responses/compact"}
	}
	if isCodexOpenAIImageRequest(opts) {
		return e.executeOpenAIImageStream(ctx, auth, req, opts)
	}
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	apiKey, baseURL := codexCreds(auth)
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}

	reporter := helps.NewExecutorUsageReporter(ctx, e, baseModel, auth)
	defer reporter.TrackFailure(ctx, &err)

	from := opts.SourceFormat
	to := sdktranslator.FromString("codex")
	originalPayloadSource := req.Payload
	if len(opts.OriginalRequest) > 0 {
		originalPayloadSource = opts.OriginalRequest
	}
	originalPayload := originalPayloadSource
	originalTranslated, body := translateCodexRequestPair(from, to, baseModel, originalPayload, req.Payload, true)

	body, err = thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return nil, err
	}

	requestedModel := helps.PayloadRequestedModel(opts, req.Model)
	requestPath := helps.PayloadRequestPath(opts)
	body = helps.ApplyPayloadConfigWithRequest(e.cfg, baseModel, to.String(), from.String(), "", body, originalTranslated, requestedModel, requestPath, opts.Headers)
	body, _ = sjson.DeleteBytes(body, "previous_response_id")
	body, _ = sjson.DeleteBytes(body, "prompt_cache_retention")
	body, _ = sjson.DeleteBytes(body, "safety_identifier")
	body, _ = sjson.DeleteBytes(body, "stream_options")
	body, _ = sjson.SetBytes(body, "model", baseModel)
	body = normalizeCodexInstructions(body)
	if e.cfg == nil || e.cfg.DisableImageGeneration == config.DisableImageGenerationOff {
		body = ensureImageGenerationTool(body, baseModel, auth)
	}
	body = sanitizeOpenAIResponsesReasoningEncryptedContent(ctx, "codex executor", body)
	body, replayScope := applyCodexReasoningReplayCache(ctx, from, req, opts, body)
	reporter.SetTranslatedReasoningEffort(body, to.String())

	url := strings.TrimSuffix(baseURL, "/") + "/responses"
	var identityState codexIdentityConfuseState
	httpReq, upstreamBody, identityState, err := e.cacheHelper(ctx, from, url, auth, req, originalPayloadSource, body)
	if err != nil {
		return nil, err
	}
	applyCodexHeaders(httpReq, auth, apiKey, true, e.cfg)
	applyCodexIdentityConfuseHeaders(httpReq.Header, &identityState)
	var authID, authLabel, authType, authValue string
	if auth != nil {
		authID = auth.ID
		authLabel = auth.Label
		authType, authValue = auth.AccountInfo()
	}
	helps.RecordAPIRequest(ctx, e.cfg, helps.UpstreamRequestLog{
		URL:       url,
		Method:    http.MethodPost,
		Headers:   httpReq.Header.Clone(),
		Body:      upstreamBody,
		Provider:  e.Identifier(),
		AuthID:    authID,
		AuthLabel: authLabel,
		AuthType:  authType,
		AuthValue: authValue,
	})

	httpClient := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	httpClient = reporter.TrackHTTPClient(httpClient)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		helps.RecordAPIResponseError(ctx, e.cfg, err)
		return nil, err
	}
	helps.RecordAPIResponseMetadata(ctx, e.cfg, httpResp.StatusCode, httpResp.Header.Clone())
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		data, readErr := io.ReadAll(httpResp.Body)
		if errClose := httpResp.Body.Close(); errClose != nil {
			log.Errorf("codex executor: close response body error: %v", errClose)
		}
		if readErr != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, readErr)
			return nil, readErr
		}
		data = applyCodexIdentityConfuseResponsePayload(data, identityState)
		clearCodexReasoningReplayOnInvalidSignature(replayScope, httpResp.StatusCode, data)
		helps.AppendAPIResponseChunk(ctx, e.cfg, data)
		helps.LogWithRequestID(ctx).Debugf("request error, error status: %d, error message: %s", httpResp.StatusCode, helps.SummarizeErrorBody(httpResp.Header.Get("Content-Type"), data))
		err = newCodexStatusErr(httpResp.StatusCode, data)
		return nil, err
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer func() {
			if errClose := httpResp.Body.Close(); errClose != nil {
				log.Errorf("codex executor: close response body error: %v", errClose)
			}
		}()
		scanner := bufio.NewScanner(httpResp.Body)
		scanner.Buffer(nil, 52_428_800) // 50MB
		var param any
		outputItemsByIndex := make(map[int64][]byte)
		var outputItemsFallback [][]byte
		for scanner.Scan() {
			line := applyCodexIdentityConfuseResponsePayload(scanner.Bytes(), identityState)
			helps.AppendAPIResponseChunk(ctx, e.cfg, line)
			translatedLine := bytes.Clone(line)

			if bytes.HasPrefix(line, dataTag) {
				data := bytes.TrimSpace(line[5:])
				if streamErr, terminalBody, ok := codexTerminalStreamErr(data); ok {
					clearCodexReasoningReplayOnInvalidSignature(replayScope, streamErr.StatusCode(), terminalBody)
					helps.RecordAPIResponseError(ctx, e.cfg, streamErr)
					reporter.PublishFailure(ctx, streamErr)
					select {
					case out <- cliproxyexecutor.StreamChunk{Err: streamErr}:
					case <-ctx.Done():
					}
					return
				}
				switch gjson.GetBytes(data, "type").String() {
				case "response.output_item.done":
					collectCodexOutputItemDone(data, outputItemsByIndex, &outputItemsFallback)
				case "response.completed":
					if detail, ok := helps.ParseCodexUsage(data); ok {
						reporter.Publish(ctx, detail)
					}
					publishCodexImageToolUsage(ctx, reporter, body, data)
					data = patchCodexCompletedOutput(data, outputItemsByIndex, outputItemsFallback)
					cacheCodexReasoningReplayFromCompleted(replayScope, data)
					translatedLine = append([]byte("data: "), data...)
				}
			}

			translatedLine = applyCodexIdentityExposeResponsePayload(translatedLine, identityState)
			chunks := sdktranslator.TranslateStream(ctx, to, from, req.Model, originalPayload, body, translatedLine, &param)
			for i := range chunks {
				select {
				case out <- cliproxyexecutor.StreamChunk{Payload: chunks[i]}:
				case <-ctx.Done():
					return
				}
			}
		}
		if errScan := scanner.Err(); errScan != nil {
			helps.RecordAPIResponseError(ctx, e.cfg, errScan)
			reporter.PublishFailure(ctx, errScan)
			select {
			case out <- cliproxyexecutor.StreamChunk{Err: errScan}:
			case <-ctx.Done():
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: httpResp.Header.Clone(), Chunks: out}, nil
}

func (e *CodexExecutor) CountTokens(ctx context.Context, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	baseModel := thinking.ParseSuffix(req.Model).ModelName

	from := opts.SourceFormat
	to := sdktranslator.FromString("codex")
	body := sdktranslator.TranslateRequest(from, to, baseModel, req.Payload, false)

	body, err := thinking.ApplyThinking(body, req.Model, from.String(), to.String(), e.Identifier())
	if err != nil {
		return cliproxyexecutor.Response{}, err
	}

	body, _ = sjson.SetBytes(body, "model", baseModel)
	body, _ = sjson.DeleteBytes(body, "previous_response_id")
	body, _ = sjson.DeleteBytes(body, "prompt_cache_retention")
	body, _ = sjson.DeleteBytes(body, "safety_identifier")
	body, _ = sjson.DeleteBytes(body, "stream_options")
	body, _ = sjson.SetBytes(body, "stream", false)
	body = normalizeCodexInstructions(body)

	enc, err := tokenizerForCodexModel(baseModel)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex executor: tokenizer init failed: %w", err)
	}

	count, err := countCodexInputTokens(enc, body)
	if err != nil {
		return cliproxyexecutor.Response{}, fmt.Errorf("codex executor: token counting failed: %w", err)
	}

	usageJSON := fmt.Sprintf(`{"response":{"usage":{"input_tokens":%d,"output_tokens":0,"total_tokens":%d}}}`, count, count)
	translated := sdktranslator.TranslateTokenCount(ctx, to, from, count, []byte(usageJSON))
	return cliproxyexecutor.Response{Payload: translated}, nil
}

func tokenizerForCodexModel(model string) (tokenizer.Codec, error) {
	sanitized := strings.ToLower(strings.TrimSpace(model))
	switch {
	case sanitized == "":
		return tokenizer.Get(tokenizer.Cl100kBase)
	case strings.HasPrefix(sanitized, "gpt-5"):
		return tokenizer.ForModel(tokenizer.GPT5)
	case strings.HasPrefix(sanitized, "gpt-4.1"):
		return tokenizer.ForModel(tokenizer.GPT41)
	case strings.HasPrefix(sanitized, "gpt-4o"):
		return tokenizer.ForModel(tokenizer.GPT4o)
	case strings.HasPrefix(sanitized, "gpt-4"):
		return tokenizer.ForModel(tokenizer.GPT4)
	case strings.HasPrefix(sanitized, "gpt-3.5"), strings.HasPrefix(sanitized, "gpt-3"):
		return tokenizer.ForModel(tokenizer.GPT35Turbo)
	default:
		return tokenizer.Get(tokenizer.Cl100kBase)
	}
}

func countCodexInputTokens(enc tokenizer.Codec, body []byte) (int64, error) {
	if enc == nil {
		return 0, fmt.Errorf("encoder is nil")
	}
	if len(body) == 0 {
		return 0, nil
	}

	root := gjson.ParseBytes(body)
	var segments []string

	if inst := strings.TrimSpace(root.Get("instructions").String()); inst != "" {
		segments = append(segments, inst)
	}

	inputItems := root.Get("input")
	if inputItems.IsArray() {
		arr := inputItems.Array()
		for i := range arr {
			item := arr[i]
			switch item.Get("type").String() {
			case "message":
				content := item.Get("content")
				if content.IsArray() {
					parts := content.Array()
					for j := range parts {
						part := parts[j]
						if text := strings.TrimSpace(part.Get("text").String()); text != "" {
							segments = append(segments, text)
						}
					}
				}
			case "function_call":
				if name := strings.TrimSpace(item.Get("name").String()); name != "" {
					segments = append(segments, name)
				}
				if args := strings.TrimSpace(item.Get("arguments").String()); args != "" {
					segments = append(segments, args)
				}
			case "function_call_output":
				if out := strings.TrimSpace(item.Get("output").String()); out != "" {
					segments = append(segments, out)
				}
			default:
				if text := strings.TrimSpace(item.Get("text").String()); text != "" {
					segments = append(segments, text)
				}
			}
		}
	}

	tools := root.Get("tools")
	if tools.IsArray() {
		tarr := tools.Array()
		for i := range tarr {
			tool := tarr[i]
			if name := strings.TrimSpace(tool.Get("name").String()); name != "" {
				segments = append(segments, name)
			}
			if desc := strings.TrimSpace(tool.Get("description").String()); desc != "" {
				segments = append(segments, desc)
			}
			if params := tool.Get("parameters"); params.Exists() {
				val := params.Raw
				if params.Type == gjson.String {
					val = params.String()
				}
				if trimmed := strings.TrimSpace(val); trimmed != "" {
					segments = append(segments, trimmed)
				}
			}
		}
	}

	textFormat := root.Get("text.format")
	if textFormat.Exists() {
		if name := strings.TrimSpace(textFormat.Get("name").String()); name != "" {
			segments = append(segments, name)
		}
		if schema := textFormat.Get("schema"); schema.Exists() {
			val := schema.Raw
			if schema.Type == gjson.String {
				val = schema.String()
			}
			if trimmed := strings.TrimSpace(val); trimmed != "" {
				segments = append(segments, trimmed)
			}
		}
	}

	text := strings.Join(segments, "\n")
	if text == "" {
		return 0, nil
	}

	count, err := enc.Count(text)
	if err != nil {
		return 0, err
	}
	return int64(count), nil
}

func (e *CodexExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	log.Debugf("codex executor: refresh called")
	if refreshed, handled, err := helps.RefreshAuthViaHome(ctx, e.cfg, auth); handled {
		return refreshed, err
	}
	if auth == nil {
		return nil, statusErr{code: 500, msg: "codex executor: auth is nil"}
	}
	var refreshToken string
	if auth.Metadata != nil {
		if v, ok := auth.Metadata["refresh_token"].(string); ok && v != "" {
			refreshToken = v
		}
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	if refreshToken != "" {
		svc := codexauth.NewCodexAuthWithProxyURL(e.cfg, auth.ProxyURL)
		td, err := svc.RefreshTokensWithRetry(ctx, refreshToken, 3)
		if err != nil {
			return nil, err
		}
		auth.Metadata["id_token"] = td.IDToken
		auth.Metadata["access_token"] = td.AccessToken
		if td.RefreshToken != "" {
			auth.Metadata["refresh_token"] = td.RefreshToken
		}
		if td.AccountID != "" {
			auth.Metadata["account_id"] = td.AccountID
		}
		auth.Metadata["email"] = td.Email
		// Use unified key in files
		auth.Metadata["expired"] = td.Expire
		auth.Metadata["type"] = "codex"
	}
	now := time.Now().UTC()
	if cliproxyauth.IsCodexOAuthLikeAuth(auth) {
		cliproxyauth.EnsureCodexQuotaRefreshMetadata(auth)
		if quotaState, blockedUntil, err := e.refreshCodexQuotaState(ctx, auth, now); err != nil {
			previous, _ := auth.GetCodexQuotaState()
			previous.RefreshStatus = "error"
			previous.RefreshError = strings.TrimSpace(err.Error())
			auth.SetCodexQuotaState(previous)
		} else {
			verifiedRecovery := false
			if blockedUntil == nil {
				if probeResetAt, ok := quotaState.CodexProbeEligibleResetAt(now); ok {
					quotaState, verifiedRecovery = e.verifyCodexQuotaRecovery(ctx, auth, quotaState, now, *probeResetAt)
				} else if windowResetAt, ok := quotaState.CodexProbeWindowResetAt(now); ok {
					verifiedRecovery = quotaState.CodexProbeVerifiedForReset(*windowResetAt)
				}
			}
			auth.SetCodexQuotaState(quotaState)
			switch {
			case blockedUntil != nil:
				cliproxyauth.ApplyCodexQuotaBlockedUntil(auth, blockedUntil)
			case verifiedRecovery:
				cliproxyauth.ApplyCodexQuotaBlockedUntil(auth, nil)
			}
		}
	}
	auth.Metadata["last_refresh"] = now.Format(time.RFC3339)
	return auth, nil
}

func (e *CodexExecutor) verifyCodexQuotaRecovery(ctx context.Context, auth *cliproxyauth.Auth, state cliproxyauth.CodexQuotaState, now, resetAt time.Time) (cliproxyauth.CodexQuotaState, bool) {
	resetAt = resetAt.UTC()
	probeAt := now.UTC()
	state.ProbeResetAt = &resetAt
	state.ProbeAt = &probeAt
	state.ProbeVerifiedAt = nil
	state.ProbeStatus = "failed"
	state.ProbeError = ""
	if auth != nil {
		cliproxyauth.ReleaseCodexStickyAuth(auth.ID)
	}

	if err := e.runCodexQuotaRecoveryProbe(ctx, auth); err != nil {
		state.ProbeStatus = "failed"
		state.ProbeError = strings.TrimSpace(err.Error())
		return state, false
	}

	state.ProbeVerifiedAt = &probeAt
	state.ProbeStatus = "verified"
	state.ProbeError = ""
	return state, state.CodexProbeVerifiedForReset(resetAt)
}

func (e *CodexExecutor) runCodexQuotaRecoveryProbe(ctx context.Context, auth *cliproxyauth.Auth) error {
	token, baseURL := codexCreds(auth)
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("codex recovery probe: access token missing")
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}
	probeURL := strings.TrimSuffix(baseURL, "/") + "/responses/compact"
	body := []byte(`{"model":"gpt-5.4-mini","instructions":"","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"ping"}]}]}`)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, probeURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("codex recovery probe: build request failed: %w", err)
	}
	applyCodexHeaders(httpReq, auth, token, false, e.cfg)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")
	httpResp, err := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(httpReq)
	if err != nil {
		return fmt.Errorf("codex recovery probe: request failed: %w", err)
	}
	defer closeHTTPResponseBody(httpResp, "codex recovery probe: close response body error")
	responseBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("codex recovery probe: read response failed: %w", err)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return fmt.Errorf("codex recovery probe: %s returned %d: %s", probeURL, httpResp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	if !codexProbeUsageEvidence(responseBody) {
		return fmt.Errorf("codex recovery probe: no usage evidence in successful response")
	}
	return nil
}

func codexProbeUsageEvidence(body []byte) bool {
	paths := []string{
		"usage.total_tokens",
		"usage.prompt_tokens",
		"usage.input_tokens",
		"usage.completion_tokens",
		"usage.output_tokens",
		"response.usage.total_tokens",
		"response.usage.prompt_tokens",
		"response.usage.input_tokens",
		"response.usage.completion_tokens",
		"response.usage.output_tokens",
	}
	for _, path := range paths {
		if gjson.GetBytes(body, path).Int() > 0 {
			return true
		}
	}
	return false
}

type codexQuotaRefreshPayload struct {
	state        cliproxyauth.CodexQuotaState
	blockedUntil *time.Time
}

func (e *CodexExecutor) refreshCodexQuotaState(ctx context.Context, auth *cliproxyauth.Auth, now time.Time) (cliproxyauth.CodexQuotaState, *time.Time, error) {
	token, baseURL := codexCreds(auth)
	if strings.TrimSpace(token) == "" {
		return cliproxyauth.CodexQuotaState{}, nil, fmt.Errorf("codex quota refresh: access token missing")
	}
	urls := codexQuotaRefreshURLs(baseURL)
	previous, _ := auth.GetCodexQuotaState()
	merged := cloneCodexQuotaState(previous)
	var blockedUntil *time.Time
	var errs []string
	hadData := false
	for _, endpoint := range urls {
		body, err := e.fetchCodexQuotaRefreshDocument(ctx, auth, token, endpoint)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		payload, ok := parseCodexQuotaRefreshPayload(body)
		if !ok {
			errs = append(errs, fmt.Sprintf("codex quota refresh: no quota data at %s", endpoint))
			continue
		}
		hadData = true
		if codexQuotaBucketHasData(payload.state.FiveHour) {
			merged.FiveHour = payload.state.FiveHour
		}
		if codexQuotaBucketHasData(payload.state.Weekly) {
			merged.Weekly = payload.state.Weekly
		}
		if payload.blockedUntil != nil && !payload.blockedUntil.IsZero() {
			until := payload.blockedUntil.UTC()
			blockedUntil = &until
		}
	}
	if !hadData {
		if len(errs) == 0 {
			return cliproxyauth.CodexQuotaState{}, nil, fmt.Errorf("codex quota refresh: no usable quota response")
		}
		return cliproxyauth.CodexQuotaState{}, nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	merged.LastRefreshAt = &now
	merged.RefreshStatus = "ok"
	merged.RefreshError = ""
	return merged, blockedUntil, nil
}

func (e *CodexExecutor) fetchCodexQuotaRefreshDocument(ctx context.Context, auth *cliproxyauth.Auth, token, rawURL string) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("codex quota refresh: build request %s: %w", rawURL, err)
	}
	applyCodexQuotaRefreshHeaders(httpReq, auth, token)
	httpReq.Header.Set("Accept", "application/json")
	httpResp, err := helps.NewProxyAwareHTTPClient(ctx, e.cfg, auth, 0).Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("codex quota refresh: request %s failed: %w", rawURL, err)
	}
	defer closeHTTPResponseBody(httpResp, "codex quota refresh: close response body error")
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("codex quota refresh: read %s failed: %w", rawURL, err)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return nil, fmt.Errorf("codex quota refresh: %s returned %d: %s", rawURL, httpResp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func applyCodexQuotaRefreshHeaders(r *http.Request, auth *cliproxyauth.Auth, token string) {
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", codexQuotaRefreshUserAgent)
	if auth != nil && auth.Metadata != nil {
		if accountID, ok := auth.Metadata["account_id"].(string); ok && strings.TrimSpace(accountID) != "" {
			r.Header.Set("Chatgpt-Account-Id", accountID)
		}
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(r, attrs)
}

func codexQuotaRefreshURLs(baseURL string) []string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		trimmed = "https://chatgpt.com/backend-api/codex"
	}
	candidates := []string{codexQuotaUsageURLFromBase(trimmed)}
	seen := make(map[string]struct{}, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if _, err := url.Parse(candidate); err != nil {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func codexQuotaUsageURLFromBase(baseURL string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return "https://chatgpt.com/backend-api/wham/usage"
	}
	if base, ok := trimSuffixFold(trimmed, "/codex/usage"); ok {
		return base + "/wham/usage"
	}
	if base, ok := trimSuffixFold(trimmed, "/usage"); ok {
		if _, ok := trimSuffixFold(base, "/wham"); ok {
			return trimmed
		}
	}
	if base, ok := trimSuffixFold(trimmed, "/codex"); ok {
		return base + "/wham/usage"
	}
	if _, ok := trimSuffixFold(trimmed, "/wham"); ok {
		return trimmed + "/usage"
	}
	if _, ok := trimSuffixFold(trimmed, "/backend-api"); ok {
		return trimmed + "/wham/usage"
	}
	return trimmed + "/usage"
}

func trimSuffixFold(value, suffix string) (string, bool) {
	if !strings.HasSuffix(strings.ToLower(value), strings.ToLower(suffix)) {
		return value, false
	}
	return value[:len(value)-len(suffix)], true
}

func parseCodexQuotaRefreshPayload(body []byte) (codexQuotaRefreshPayload, bool) {
	payload := codexQuotaRefreshPayload{}
	now := time.Now().UTC()
	payload.state.FiveHour = parseCodexQuotaBucket(body,
		"quota.five_hour", "quota.fiveHour", "five_hour", "fiveHour",
		"usage.five_hour", "usage.fiveHour", "ratelimits.five_hour", "ratelimits.fiveHour",
	)
	payload.state.Weekly = parseCodexQuotaBucket(body,
		"quota.weekly", "quota.weekly_window", "weekly", "weekly_window",
		"usage.weekly", "usage.weekly_window", "ratelimits.weekly", "ratelimits.weekly_window",
	)
	if !codexQuotaBucketHasData(payload.state.Weekly) {
		payload.state.Weekly = parseCodexQuotaWindowByDuration(body, now, "rate_limit", 7*24*time.Hour)
		if !codexQuotaBucketHasData(payload.state.Weekly) {
			payload.state.Weekly = parseCodexQuotaBucketAt(body, now, "rate_limit.secondary_window")
		}
	}
	if !codexQuotaBucketHasData(payload.state.FiveHour) {
		payload.state.FiveHour = parseCodexQuotaWindowByDuration(body, now, "rate_limit", 5*time.Hour)
		if !codexQuotaBucketHasData(payload.state.FiveHour) {
			payload.state.FiveHour = parseCodexQuotaBucketAt(body, now, "rate_limit.primary_window")
		}
	}
	mergeCodexAdditionalRateLimitBuckets(body, &payload.state)
	if blockedUntil, ok := firstTimePath(body,
		"quota_blocked_until", "quota.blocked_until", "quota.blockedUntil",
		"blocked_until", "blockedUntil", "ratelimits.blocked_until", "ratelimits.blockedUntil",
		"error.resets_at", "rate_limit.blocked_until", "rate_limit.blockedUntil",
		"rate_limit.primary_window.blocked_until", "rate_limit.primary_window.blockedUntil",
		"rate_limit.secondary_window.blocked_until", "rate_limit.secondary_window.blockedUntil",
	); ok {
		payload.blockedUntil = &blockedUntil
	}
	return payload, codexQuotaBucketHasData(payload.state.FiveHour) || codexQuotaBucketHasData(payload.state.Weekly) || payload.blockedUntil != nil
}

func parseCodexQuotaBucket(body []byte, prefixes ...string) cliproxyauth.CodexQuotaBucket {
	return parseCodexQuotaBucketAt(body, time.Now().UTC(), prefixes...)
}

func parseCodexQuotaBucketAt(body []byte, now time.Time, prefixes ...string) cliproxyauth.CodexQuotaBucket {
	for _, prefix := range prefixes {
		bucket := cliproxyauth.CodexQuotaBucket{}
		if remaining, ok := firstFloatPath(body,
			codexQuotaFieldPath(prefix, "remaining"),
			codexQuotaFieldPath(prefix, "remaining_quota"),
			codexQuotaFieldPath(prefix, "available"),
			codexQuotaFieldPath(prefix, "left"),
		); ok {
			bucket.Remaining = &remaining
		}
		if limit, ok := firstFloatPath(body,
			codexQuotaFieldPath(prefix, "limit"),
			codexQuotaFieldPath(prefix, "quota"),
			codexQuotaFieldPath(prefix, "total"),
			codexQuotaFieldPath(prefix, "max"),
		); ok {
			bucket.Limit = &limit
		}
		if resetAt, ok := firstQuotaResetPath(body, now,
			codexQuotaFieldPath(prefix, "reset_at"),
			codexQuotaFieldPath(prefix, "resetAt"),
			codexQuotaFieldPath(prefix, "resets_at"),
			codexQuotaFieldPath(prefix, "resetsAt"),
			codexQuotaFieldPath(prefix, "next_reset_at"),
			codexQuotaFieldPath(prefix, "reset_after_seconds"),
			codexQuotaFieldPath(prefix, "resetAfterSeconds"),
			codexQuotaFieldPath(prefix, "resets_after_seconds"),
			codexQuotaFieldPath(prefix, "resetsAfterSeconds"),
		); ok {
			bucket.ResetAt = &resetAt
		}
		if bucket.Remaining == nil {
			if usedPercent, ok := firstFloatPath(body,
				codexQuotaFieldPath(prefix, "used_percent"),
				codexQuotaFieldPath(prefix, "usedPercent"),
			); ok {
				limit := 100.0
				remaining := limit - usedPercent
				if remaining < 0 {
					remaining = 0
				}
				if bucket.Limit == nil {
					bucket.Limit = &limit
				}
				bucket.Remaining = &remaining
			}
		}
		if codexQuotaBucketHasData(bucket) {
			return bucket
		}
	}
	return cliproxyauth.CodexQuotaBucket{}
}

func parseCodexQuotaWindowByDuration(body []byte, now time.Time, prefix string, target time.Duration) cliproxyauth.CodexQuotaBucket {
	for _, windowName := range []string{"primary_window", "primaryWindow", "secondary_window", "secondaryWindow"} {
		path := codexQuotaFieldPath(prefix, windowName)
		result := gjson.GetBytes(body, path)
		if !result.Exists() {
			continue
		}
		seconds, ok := firstFloatPath([]byte(result.Raw), "limit_window_seconds", "limitWindowSeconds")
		if !ok || time.Duration(seconds*float64(time.Second)) != target {
			continue
		}
		bucket := parseCodexQuotaBucketAt([]byte(result.Raw), now, "")
		if codexQuotaBucketHasData(bucket) {
			return bucket
		}
	}
	return cliproxyauth.CodexQuotaBucket{}
}

func codexQuotaFieldPath(prefix, field string) string {
	prefix = strings.TrimSpace(prefix)
	field = strings.TrimSpace(field)
	if prefix == "" {
		return field
	}
	if field == "" {
		return prefix
	}
	return prefix + "." + field
}

func mergeCodexAdditionalRateLimitBuckets(body []byte, state *cliproxyauth.CodexQuotaState) {
	if state == nil {
		return
	}
	for _, path := range []string{"rate_limit.additional_rate_limits", "additional_rate_limits"} {
		result := gjson.GetBytes(body, path)
		if !result.Exists() {
			continue
		}
		for _, item := range result.Array() {
			bucket := parseCodexQuotaBucketAt([]byte(item.Raw), time.Now().UTC(), "")
			if !codexQuotaBucketHasData(bucket) {
				continue
			}
			switch codexQuotaBucketWindowKind([]byte(item.Raw)) {
			case "weekly":
				if !codexQuotaBucketHasData(state.Weekly) {
					state.Weekly = bucket
				}
			case "five_hour":
				if !codexQuotaBucketHasData(state.FiveHour) {
					state.FiveHour = bucket
				}
			}
		}
	}
}

func codexQuotaBucketWindowKind(body []byte) string {
	label, _ := firstStringPath(body,
		"name", "key", "id", "window", "window_name", "windowName", "label", "slug",
	)
	label = strings.ToLower(strings.TrimSpace(label))
	if strings.Contains(label, "week") {
		return "weekly"
	}
	if (strings.Contains(label, "five") || strings.Contains(label, "5")) && strings.Contains(label, "hour") {
		return "five_hour"
	}
	if strings.Contains(label, "secondary") {
		return "weekly"
	}
	if strings.Contains(label, "primary") {
		return "five_hour"
	}
	if seconds, ok := firstFloatPath(body,
		"window_seconds", "duration_seconds", "interval_seconds", "reset_interval_seconds", "limit_window_seconds", "limitWindowSeconds",
	); ok {
		switch {
		case seconds >= 6*24*60*60:
			return "weekly"
		case seconds >= 4*60*60 && seconds <= 6*60*60:
			return "five_hour"
		}
	}
	return ""
}

func codexQuotaBucketHasData(bucket cliproxyauth.CodexQuotaBucket) bool {
	return bucket.Remaining != nil || bucket.Limit != nil || bucket.ResetAt != nil
}

func cloneCodexQuotaState(state cliproxyauth.CodexQuotaState) cliproxyauth.CodexQuotaState {
	cloned := cliproxyauth.CodexQuotaState{
		RefreshStatus: state.RefreshStatus,
		RefreshError:  state.RefreshError,
		ProbeStatus:   state.ProbeStatus,
		ProbeError:    state.ProbeError,
	}
	if state.FiveHour.Remaining != nil {
		value := *state.FiveHour.Remaining
		cloned.FiveHour.Remaining = &value
	}
	if state.FiveHour.Limit != nil {
		value := *state.FiveHour.Limit
		cloned.FiveHour.Limit = &value
	}
	if state.FiveHour.ResetAt != nil {
		value := state.FiveHour.ResetAt.UTC()
		cloned.FiveHour.ResetAt = &value
	}
	if state.Weekly.Remaining != nil {
		value := *state.Weekly.Remaining
		cloned.Weekly.Remaining = &value
	}
	if state.Weekly.Limit != nil {
		value := *state.Weekly.Limit
		cloned.Weekly.Limit = &value
	}
	if state.Weekly.ResetAt != nil {
		value := state.Weekly.ResetAt.UTC()
		cloned.Weekly.ResetAt = &value
	}
	if state.LastRefreshAt != nil {
		value := state.LastRefreshAt.UTC()
		cloned.LastRefreshAt = &value
	}
	if state.ProbeResetAt != nil {
		value := state.ProbeResetAt.UTC()
		cloned.ProbeResetAt = &value
	}
	if state.ProbeAt != nil {
		value := state.ProbeAt.UTC()
		cloned.ProbeAt = &value
	}
	if state.ProbeVerifiedAt != nil {
		value := state.ProbeVerifiedAt.UTC()
		cloned.ProbeVerifiedAt = &value
	}
	return cloned
}

func firstFloatPath(body []byte, paths ...string) (float64, bool) {
	for _, path := range paths {
		result := gjson.GetBytes(body, path)
		if !result.Exists() {
			continue
		}
		switch result.Type {
		case gjson.Number:
			return result.Float(), true
		case gjson.String:
			if value, ok := cliproxyauthFloatString(result.String()); ok {
				return value, true
			}
		}
	}
	return 0, false
}

func firstTimePath(body []byte, paths ...string) (time.Time, bool) {
	for _, path := range paths {
		result := gjson.GetBytes(body, path)
		if !result.Exists() {
			continue
		}
		switch result.Type {
		case gjson.Number:
			unix := result.Int()
			if unix > 0 {
				return time.Unix(unix, 0).UTC(), true
			}
		case gjson.String:
			if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(result.String())); err == nil {
				return parsed.UTC(), true
			}
		}
	}
	return time.Time{}, false
}

func firstQuotaResetPath(body []byte, now time.Time, paths ...string) (time.Time, bool) {
	absolutePaths := make([]string, 0, len(paths))
	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		if strings.HasSuffix(lower, "seconds") {
			result := gjson.GetBytes(body, trimmed)
			if !result.Exists() {
				continue
			}
			seconds := 0.0
			switch result.Type {
			case gjson.Number:
				seconds = result.Float()
			case gjson.String:
				if value, ok := cliproxyauthFloatString(result.String()); ok {
					seconds = value
				}
			}
			if seconds > 0 {
				return now.Add(time.Duration(seconds * float64(time.Second))).UTC(), true
			}
			continue
		}
		absolutePaths = append(absolutePaths, trimmed)
	}
	return firstTimePath(body, absolutePaths...)
}

func firstStringPath(body []byte, paths ...string) (string, bool) {
	for _, path := range paths {
		result := gjson.GetBytes(body, path)
		if !result.Exists() || result.Type != gjson.String {
			continue
		}
		value := strings.TrimSpace(result.String())
		if value != "" {
			return value, true
		}
	}
	return "", false
}

func cliproxyauthFloatString(raw string) (float64, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, false
	}
	result := gjson.Parse(trimmed)
	if result.Type != gjson.Number {
		return 0, false
	}
	return result.Float(), true
}

type codexIdentityConfuseState struct {
	enabled                bool
	authID                 string
	originalPromptCacheKey string
	promptCacheKey         string
	turnIDs                []codexIdentityReplacement
}

type codexIdentityReplacement struct {
	original string
	confused string
}

func (e *CodexExecutor) cacheHelper(ctx context.Context, from sdktranslator.Format, url string, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, userPayload []byte, rawJSON []byte) (*http.Request, []byte, codexIdentityConfuseState, error) {
	var cache helps.CodexCache
	if sourceFormatEqual(from, sdktranslator.FormatClaude) {
		if cached, ok := codexClaudeCodePromptCache(req); ok {
			cache = cached
		}
	} else if sourceFormatEqual(from, sdktranslator.FormatOpenAIResponse) {
		promptCacheKey := gjson.GetBytes(req.Payload, "prompt_cache_key")
		if promptCacheKey.Exists() {
			cache.ID = promptCacheKey.String()
		}
	} else if sourceFormatEqual(from, sdktranslator.FormatOpenAI) {
		if apiKey := strings.TrimSpace(helps.APIKeyFromContext(ctx)); apiKey != "" {
			cache.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache:"+apiKey)).String()
		}
	}

	if cache.ID != "" {
		rawJSON, _ = sjson.SetBytes(rawJSON, "prompt_cache_key", cache.ID)
	}
	var identityState codexIdentityConfuseState
	rawJSON, identityState = applyCodexIdentityConfuseBody(e.cfg, auth, userPayload, rawJSON)
	if identityState.promptCacheKey != "" {
		cache.ID = identityState.promptCacheKey
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(rawJSON))
	if err != nil {
		return nil, nil, codexIdentityConfuseState{}, err
	}
	if cache.ID != "" {
		httpReq.Header.Set("Session_id", cache.ID)
	}
	return httpReq, rawJSON, identityState, nil
}

func applyCodexIdentityConfuseBody(cfg *config.Config, auth *cliproxyauth.Auth, userPayload []byte, rawJSON []byte) ([]byte, codexIdentityConfuseState) {
	if !codexIdentityConfuseEnabled(cfg) || auth == nil || strings.TrimSpace(auth.ID) == "" || len(rawJSON) == 0 {
		return rawJSON, codexIdentityConfuseState{}
	}

	state := codexIdentityConfuseState{enabled: true, authID: strings.TrimSpace(auth.ID)}
	if promptCacheKey := strings.TrimSpace(gjson.GetBytes(userPayload, "prompt_cache_key").String()); promptCacheKey != "" {
		state.originalPromptCacheKey = promptCacheKey
		state.promptCacheKey = codexIdentityConfuseUUID(auth.ID, "prompt-cache", promptCacheKey)
		rawJSON, _ = sjson.SetBytes(rawJSON, "prompt_cache_key", state.promptCacheKey)
	}
	if installationID := strings.TrimSpace(gjson.GetBytes(userPayload, "client_metadata.x-codex-installation-id").String()); installationID != "" {
		rawJSON, _ = sjson.SetBytes(rawJSON, "client_metadata.x-codex-installation-id", codexIdentityConfuseUUID(auth.ID, "installation", installationID))
	}
	if turnMetadata := strings.TrimSpace(gjson.GetBytes(rawJSON, "client_metadata.x-codex-turn-metadata").String()); turnMetadata != "" {
		rawJSON, _ = sjson.SetBytes(rawJSON, "client_metadata.x-codex-turn-metadata", applyCodexTurnMetadataIdentityConfuse(turnMetadata, &state))
	}
	if state.promptCacheKey != "" {
		if windowID := strings.TrimSpace(gjson.GetBytes(rawJSON, "client_metadata.x-codex-window-id").String()); windowID != "" {
			rawJSON, _ = sjson.SetBytes(rawJSON, "client_metadata.x-codex-window-id", state.promptCacheKey+":0")
		}
	}

	return rawJSON, state
}

func applyCodexIdentityConfuseHeaders(headers http.Header, state *codexIdentityConfuseState) {
	if headers == nil {
		return
	}
	if state == nil || !state.enabled {
		return
	}

	if rawTurnMetadata := strings.TrimSpace(headers.Get("X-Codex-Turn-Metadata")); rawTurnMetadata != "" {
		headers.Set("X-Codex-Turn-Metadata", applyCodexTurnMetadataIdentityConfuse(rawTurnMetadata, state))
	}
	if state.promptCacheKey == "" {
		return
	}

	setCodexSessionHeaderCasePreserved(headers, "Session_id", state.promptCacheKey)
	if headerValueCaseInsensitive(headers, "Conversation_id") != "" {
		setHeaderCasePreserved(headers, "Conversation_id", state.promptCacheKey)
	}
	headers.Set("X-Client-Request-Id", state.promptCacheKey)
	headers.Set("Thread-Id", state.promptCacheKey)
	headers.Set("X-Codex-Window-Id", state.promptCacheKey+":0")
}

func applyCodexTurnMetadataIdentityConfuse(rawTurnMetadata string, state *codexIdentityConfuseState) string {
	updatedTurnMetadata := rawTurnMetadata
	if state == nil || !state.enabled {
		return updatedTurnMetadata
	}
	if state.promptCacheKey != "" && gjson.Get(rawTurnMetadata, "prompt_cache_key").Exists() {
		updatedTurnMetadata, _ = sjson.Set(updatedTurnMetadata, "prompt_cache_key", state.promptCacheKey)
	} else if state.promptCacheKey != "" && state.originalPromptCacheKey != "" {
		updatedTurnMetadata = strings.ReplaceAll(updatedTurnMetadata, state.originalPromptCacheKey, state.promptCacheKey)
	}
	if turnID := strings.TrimSpace(gjson.Get(rawTurnMetadata, "turn_id").String()); turnID != "" {
		updatedTurnMetadata, _ = sjson.Set(updatedTurnMetadata, "turn_id", state.confuseTurnID(turnID))
	}
	if state.promptCacheKey != "" && gjson.Get(rawTurnMetadata, "window_id").Exists() {
		updatedTurnMetadata, _ = sjson.Set(updatedTurnMetadata, "window_id", state.promptCacheKey+":0")
	}
	return updatedTurnMetadata
}

func applyCodexIdentityConfuseResponsePayload(payload []byte, state codexIdentityConfuseState) []byte {
	payload = replaceCodexIdentityResponsePayload(payload, state.originalPromptCacheKey, state.promptCacheKey)
	for _, turnID := range state.turnIDs {
		payload = replaceCodexIdentityResponsePayload(payload, turnID.original, turnID.confused)
	}
	return payload
}

func applyCodexIdentityExposeResponsePayload(payload []byte, state codexIdentityConfuseState) []byte {
	payload = replaceCodexIdentityResponsePayload(payload, state.promptCacheKey, state.originalPromptCacheKey)
	for _, turnID := range state.turnIDs {
		payload = replaceCodexIdentityResponsePayload(payload, turnID.confused, turnID.original)
	}
	return payload
}

func (state *codexIdentityConfuseState) confuseTurnID(turnID string) string {
	turnID = strings.TrimSpace(turnID)
	if state == nil || !state.enabled || strings.TrimSpace(state.authID) == "" || turnID == "" {
		return turnID
	}
	for _, replacement := range state.turnIDs {
		if replacement.original == turnID || replacement.confused == turnID {
			return replacement.confused
		}
	}
	confusedTurnID := codexIdentityConfuseUUID(state.authID, "turn", turnID)
	state.turnIDs = append(state.turnIDs, codexIdentityReplacement{original: turnID, confused: confusedTurnID})
	return confusedTurnID
}

func replaceCodexIdentityResponsePayload(payload []byte, from string, to string) []byte {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)
	if len(payload) == 0 || from == "" || to == "" || from == to || !bytes.Contains(payload, []byte(from)) {
		return payload
	}
	return bytes.ReplaceAll(payload, []byte(from), []byte(to))
}

func codexIdentityConfuseEnabled(cfg *config.Config) bool {
	if cfg == nil || !cfg.Codex.IdentityConfuse {
		return false
	}
	strategy := strings.ToLower(strings.TrimSpace(cfg.Routing.Strategy))
	return cfg.Routing.SessionAffinity || strategy == "fill-first" || strategy == "fillfirst" || strategy == "ff"
}

func codexIdentityConfuseUUID(authID string, kind string, value string) string {
	name := strings.Join([]string{"cli-proxy-api", "codex", "identity-confuse", kind, strings.TrimSpace(authID), strings.TrimSpace(value)}, ":")
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()
}

func applyCodexHeaders(r *http.Request, auth *cliproxyauth.Auth, token string, stream bool, cfg *config.Config) {
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)

	var ginHeaders http.Header
	if ginCtx, ok := r.Context().Value("gin").(*gin.Context); ok && ginCtx != nil && ginCtx.Request != nil {
		ginHeaders = ginCtx.Request.Header
	}

	if ginHeaders.Get("X-Codex-Beta-Features") != "" {
		r.Header.Set("X-Codex-Beta-Features", ginHeaders.Get("X-Codex-Beta-Features"))
	}
	misc.EnsureHeader(r.Header, ginHeaders, "Version", "")
	misc.EnsureHeader(r.Header, ginHeaders, "X-Codex-Turn-Metadata", "")
	misc.EnsureHeader(r.Header, ginHeaders, "X-Client-Request-Id", "")
	cfgUserAgent, _ := codexHeaderDefaults(cfg, auth)
	ensureHeaderWithConfigPrecedence(r.Header, ginHeaders, "User-Agent", cfgUserAgent, codexUserAgent)

	if strings.Contains(r.Header.Get("User-Agent"), "Mac OS") {
		misc.EnsureHeader(r.Header, ginHeaders, "Session_id", uuid.NewString())
	}

	if stream {
		r.Header.Set("Accept", "text/event-stream")
	} else {
		r.Header.Set("Accept", "application/json")
	}
	r.Header.Set("Connection", "Keep-Alive")

	isAPIKey := false
	if auth != nil && auth.Attributes != nil {
		if v := strings.TrimSpace(auth.Attributes["api_key"]); v != "" {
			isAPIKey = true
		}
	}
	if originator := strings.TrimSpace(ginHeaders.Get("Originator")); originator != "" {
		r.Header.Set("Originator", originator)
	} else if !isAPIKey {
		r.Header.Set("Originator", codexOriginator)
	}
	if !isAPIKey {
		if auth != nil && auth.Metadata != nil {
			if accountID, ok := auth.Metadata["account_id"].(string); ok {
				r.Header.Set("Chatgpt-Account-Id", accountID)
			}
		}
	}
	var attrs map[string]string
	if auth != nil {
		attrs = auth.Attributes
	}
	util.ApplyCustomHeadersFromAttrs(r, attrs)
}

func newCodexStatusErr(statusCode int, body []byte) statusErr {
	errCode := statusCode
	if isCodexModelCapacityError(body) {
		errCode = http.StatusTooManyRequests
	}
	body = classifyCodexStatusError(errCode, body)
	err := statusErr{code: errCode, msg: string(body)}
	if retryAfter := parseCodexRetryAfter(errCode, body, time.Now()); retryAfter != nil {
		err.retryAfter = retryAfter
	}
	return err
}

func classifyCodexStatusError(statusCode int, body []byte) []byte {
	code, errType, ok := codexStatusErrorClassification(statusCode, body)
	if !ok {
		return body
	}
	message := gjson.GetBytes(body, "error.message").String()
	if message == "" {
		message = gjson.GetBytes(body, "message").String()
	}
	if message == "" {
		message = strings.TrimSpace(string(body))
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	out := []byte(`{"error":{}}`)
	out, _ = sjson.SetBytes(out, "error.message", message)
	out, _ = sjson.SetBytes(out, "error.type", errType)
	out, _ = sjson.SetBytes(out, "error.code", code)
	return out
}

func codexStatusErrorClassification(statusCode int, body []byte) (code string, errType string, ok bool) {
	errorMessage := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.message").String()))
	if errorMessage == "" {
		errorMessage = strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "message").String()))
	}
	lower := strings.ToLower(strings.TrimSpace(string(body)))
	upstreamCode := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.code").String()))
	upstreamType := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.type").String()))
	isInvalidRequest := upstreamType == "" || upstreamType == "invalid_request_error"

	switch {
	case statusCode == http.StatusRequestEntityTooLarge || upstreamCode == "context_length_exceeded" || upstreamCode == "context_too_large" || isInvalidRequest && (strings.Contains(errorMessage, "context length") || strings.Contains(errorMessage, "context_length") || strings.Contains(errorMessage, "maximum context") || strings.Contains(errorMessage, "too many tokens")):
		return "context_too_large", "invalid_request_error", true
	case strings.Contains(lower, "invalid signature in thinking block") || strings.Contains(lower, "invalid_encrypted_content"):
		return "thinking_signature_invalid", "invalid_request_error", true
	case upstreamCode == "previous_response_not_found" || strings.Contains(lower, "previous_response_not_found") || strings.Contains(lower, "previous_response_id") && strings.Contains(lower, "not found"):
		return "previous_response_not_found", "invalid_request_error", true
	case statusCode == http.StatusUnauthorized || upstreamType == "authentication_error" || upstreamCode == "invalid_api_key" || strings.Contains(lower, "invalid or expired token") || strings.Contains(lower, "refresh_token_reused"):
		return "auth_unavailable", "authentication_error", true
	default:
		return "", "", false
	}
}

func normalizeCodexInstructions(body []byte) []byte {
	instructions := gjson.GetBytes(body, "instructions")
	if !instructions.Exists() || instructions.Type == gjson.Null {
		body, _ = sjson.SetBytes(body, "instructions", "")
	}
	return body
}

var imageGenToolJSON = []byte(`{"type":"image_generation","output_format":"png"}`)
var imageGenToolArrayJSON = []byte(`[{"type":"image_generation","output_format":"png"}]`)

func isCodexFreePlanAuth(auth *cliproxyauth.Auth) bool {
	if auth == nil || auth.Attributes == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(auth.Attributes["plan_type"]), "free")
}

func ensureImageGenerationTool(body []byte, baseModel string, auth *cliproxyauth.Auth) []byte {
	if strings.HasSuffix(baseModel, "spark") {
		return body
	}
	if isCodexFreePlanAuth(auth) {
		return body
	}

	tools := gjson.GetBytes(body, "tools")
	if !tools.Exists() || !tools.IsArray() {
		body, _ = sjson.SetRawBytes(body, "tools", imageGenToolArrayJSON)
		return body
	}
	for _, t := range tools.Array() {
		if t.Get("type").String() == "image_generation" {
			return body
		}
	}
	body, _ = sjson.SetRawBytes(body, "tools.-1", imageGenToolJSON)
	return body
}

func publishCodexImageToolUsage(ctx context.Context, reporter *helps.UsageReporter, body []byte, completedData []byte) {
	detail, ok := helps.ParseCodexImageToolUsage(completedData)
	if !ok {
		return
	}
	reporter.EnsurePublished(ctx)
	reporter.PublishAdditionalModel(ctx, codexImageGenerationToolModel(body), detail)
}

func codexImageGenerationToolModel(body []byte) string {
	tools := gjson.GetBytes(body, "tools")
	if tools.IsArray() {
		for _, tool := range tools.Array() {
			if tool.Get("type").String() != "image_generation" {
				continue
			}
			if model := strings.TrimSpace(tool.Get("model").String()); model != "" {
				return model
			}
			break
		}
	}
	return codexDefaultImageToolModel
}

func isCodexModelCapacityError(errorBody []byte) bool {
	if len(errorBody) == 0 {
		return false
	}
	candidates := []string{
		gjson.GetBytes(errorBody, "error.message").String(),
		gjson.GetBytes(errorBody, "message").String(),
		string(errorBody),
	}
	for _, candidate := range candidates {
		lower := strings.ToLower(strings.TrimSpace(candidate))
		if lower == "" {
			continue
		}
		if strings.Contains(lower, "selected model is at capacity") ||
			strings.Contains(lower, "model is at capacity. please try a different model") {
			return true
		}
	}
	return false
}

func parseCodexRetryAfter(statusCode int, errorBody []byte, now time.Time) *time.Duration {
	if statusCode != http.StatusTooManyRequests || len(errorBody) == 0 {
		return nil
	}
	if strings.TrimSpace(gjson.GetBytes(errorBody, "error.type").String()) != "usage_limit_reached" {
		return nil
	}
	if resetsAt := gjson.GetBytes(errorBody, "error.resets_at").Int(); resetsAt > 0 {
		resetAtTime := time.Unix(resetsAt, 0)
		if resetAtTime.After(now) {
			retryAfter := resetAtTime.Sub(now)
			return &retryAfter
		}
	}
	if resetsInSeconds := gjson.GetBytes(errorBody, "error.resets_in_seconds").Int(); resetsInSeconds > 0 {
		retryAfter := time.Duration(resetsInSeconds) * time.Second
		return &retryAfter
	}
	return nil
}

func codexCreds(a *cliproxyauth.Auth) (apiKey, baseURL string) {
	if a == nil {
		return "", ""
	}
	if a.Attributes != nil {
		apiKey = a.Attributes["api_key"]
		baseURL = a.Attributes["base_url"]
	}
	if apiKey == "" && a.Metadata != nil {
		if v, ok := a.Metadata["access_token"].(string); ok {
			apiKey = v
		}
	}
	return
}

func (e *CodexExecutor) resolveCodexConfig(auth *cliproxyauth.Auth) *config.CodexKey {
	if auth == nil || e.cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range e.cfg.CodexKey {
		entry := &e.cfg.CodexKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && attrBase != "" {
			if strings.EqualFold(cfgKey, attrKey) && strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	if attrKey != "" {
		for i := range e.cfg.CodexKey {
			entry := &e.cfg.CodexKey[i]
			if strings.EqualFold(strings.TrimSpace(entry.APIKey), attrKey) {
				return entry
			}
		}
	}
	return nil
}
