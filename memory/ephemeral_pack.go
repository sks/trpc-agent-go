//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//
//

package memory

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// DefaultEphemeralPackMaxTokens is the default token budget for an
	// ephemeral <memory-context> pack when neither MaxTokens nor MaxChars
	// is specified.
	DefaultEphemeralPackMaxTokens = 1024

	// DefaultCharsPerToken is the approximate characters-per-token ratio
	// used to translate MaxTokens into a character ceiling when MaxChars is 0.
	DefaultCharsPerToken = 4

	// DefaultToolOutcomeSummaryMaxLen is the default maximum rune length for
	// the summary tail of a 1-line tool outcome summary.
	DefaultToolOutcomeSummaryMaxLen = 160
)

// MemoryCitation represents a single cited memory snippet inside an ephemeral
// <memory-context> block.
type MemoryCitation struct {
	SourceID  string    `json:"source_id"`
	Category  string    `json:"category"`
	UpdatedAt time.Time `json:"updated_at"`
	Score     float64   `json:"score,omitempty"`
	Snippet   string    `json:"snippet"`
}

// FormatCitation Tag renders the bracketed citation prefix `[source_id|category|updated_at]`.
func (c MemoryCitation) FormatCitationTag() string {
	sourceID := sanitizeSingleLine(c.SourceID)
	if sourceID == "" {
		sourceID = "unknown"
	}
	category := sanitizeSingleLine(c.Category)
	if category == "" {
		category = string(KindFact)
	}
	updatedAt := "unknown"
	if !c.UpdatedAt.IsZero() {
		updatedAt = c.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("[%s|%s|%s]", sourceID, category, updatedAt)
}

// CitationFromEntry converts a stored memory Entry into a MemoryCitation.
func CitationFromEntry(entry *Entry) (MemoryCitation, bool) {
	if entry == nil || entry.Memory == nil {
		return MemoryCitation{}, false
	}
	snippet := strings.TrimSpace(entry.Memory.Memory)
	if snippet == "" {
		return MemoryCitation{}, false
	}
	category := string(entry.Memory.Kind)
	if category == "" && len(entry.Memory.Topics) > 0 {
		category = strings.TrimSpace(entry.Memory.Topics[0])
	}
	if category == "" {
		category = string(KindFact)
	}
	updatedAt := entry.UpdatedAt
	if updatedAt.IsZero() && entry.Memory.LastUpdated != nil {
		updatedAt = *entry.Memory.LastUpdated
	}
	if updatedAt.IsZero() {
		updatedAt = entry.CreatedAt
	}
	return MemoryCitation{
		SourceID:  entry.ID,
		Category:  category,
		UpdatedAt: updatedAt,
		Score:     entry.Score,
		Snippet:   snippet,
	}, true
}

// EphemeralPackBuilder assembles recalled memory citations into a token/char-budgeted
// XML `<memory-context>` block suitable for per-turn ephemeral injection without
// mutating the static system prompt.
type EphemeralPackBuilder struct {
	// MaxTokens is the approximate token budget for the rendered block body.
	// When MaxChars is 0 and MaxTokens > 0, MaxChars is derived as MaxTokens * 4.
	MaxTokens int

	// MaxChars is the hard character (rune) budget for the rendered citations
	// inside the <memory-context> block. If both MaxChars and MaxTokens are <= 0,
	// DefaultEphemeralPackMaxTokens * DefaultCharsPerToken is used.
	MaxChars int
}

// NewEphemeralPackBuilder returns an EphemeralPackBuilder configured with the
// given token and character budgets.
func NewEphemeralPackBuilder(maxTokens, maxChars int) *EphemeralPackBuilder {
	return &EphemeralPackBuilder{
		MaxTokens: maxTokens,
		MaxChars:  maxChars,
	}
}

func (b *EphemeralPackBuilder) effectiveMaxChars() int {
	if b == nil {
		return DefaultEphemeralPackMaxTokens * DefaultCharsPerToken
	}
	if b.MaxChars > 0 && b.MaxTokens > 0 {
		tokenChars := b.MaxTokens * DefaultCharsPerToken
		if tokenChars < b.MaxChars {
			return tokenChars
		}
		return b.MaxChars
	}
	if b.MaxChars > 0 {
		return b.MaxChars
	}
	if b.MaxTokens > 0 {
		return b.MaxTokens * DefaultCharsPerToken
	}
	return DefaultEphemeralPackMaxTokens * DefaultCharsPerToken
}

// BuildEntries converts a slice of memory entries into citations and renders
// an ephemeral `<memory-context>` XML block within the configured budget.
func (b *EphemeralPackBuilder) BuildEntries(entries []*Entry) string {
	if len(entries) == 0 {
		return ""
	}
	citations := make([]MemoryCitation, 0, len(entries))
	for _, entry := range entries {
		citation, ok := CitationFromEntry(entry)
		if !ok {
			continue
		}
		citations = append(citations, citation)
	}
	return b.Build(citations)
}

// Build renders the provided citations into an XML `<memory-context>` block
// (`<memory-context>\n- [source_id|category|updated_at] snippet\n</memory-context>`)
// respecting the builder's character/token budget. Returns "" if no citations
// have non-empty snippets or fit within the budget.
func (b *EphemeralPackBuilder) Build(citations []MemoryCitation) string {
	if len(citations) == 0 {
		return ""
	}
	budget := b.effectiveMaxChars()
	if budget <= 0 {
		return ""
	}

	var body strings.Builder
	usedRunes := 0
	included := 0

	for _, c := range citations {
		snippet := sanitizeSingleLine(c.Snippet)
		if snippet == "" {
			continue
		}
		prefix := "- " + c.FormatCitationTag() + " "
		prefixRunes := utf8.RuneCountInString(prefix)
		remaining := budget - usedRunes
		if included > 0 {
			remaining-- // account for newline separator
		}
		if remaining <= prefixRunes {
			break
		}

		allowedSnippetRunes := remaining - prefixRunes
		truncatedSnippet := truncateRunes(snippet, allowedSnippetRunes)
		if truncatedSnippet == "" {
			break
		}

		if included > 0 {
			body.WriteByte('\n')
			usedRunes++
		}
		body.WriteString(prefix)
		body.WriteString(truncatedSnippet)
		usedRunes += prefixRunes + utf8.RuneCountInString(truncatedSnippet)
		included++
	}

	if included == 0 {
		return ""
	}
	return "<memory-context>\n" + body.String() + "\n</memory-context>"
}

// ToolOutcomeSummary holds structured metadata for a 1-line argument-free tool
// outcome summary suitable for episodic or session memory.
type ToolOutcomeSummary struct {
	ToolName string `json:"tool_name"`
	CallID   string `json:"call_id"`
	Status   string `json:"status"`
	Summary  string `json:"summary"`
}

// NewToolOutcomeSummary builds a structured ToolOutcomeSummary without raw tool arguments.
func NewToolOutcomeSummary(toolName, callID string, isError bool, rawPreview string, maxLen int) ToolOutcomeSummary {
	name := sanitizeToken(toolName, "unknown")
	id := sanitizeToken(callID, "none")
	status := "ok"
	if isError {
		status = "error"
	}
	if maxLen <= 0 {
		maxLen = DefaultToolOutcomeSummaryMaxLen
	}
	summary := truncateRunes(sanitizeSingleLine(rawPreview), maxLen)
	if summary == "" {
		summary = status
	}
	return ToolOutcomeSummary{
		ToolName: name,
		CallID:   id,
		Status:   status,
		Summary:  summary,
	}
}

// String renders the 1-line argument-free tool outcome summary:
// `[tool_outcome] tool=<name> id=<callID> status=<ok|error> summary=...`
func (t ToolOutcomeSummary) String() string {
	name := sanitizeToken(t.ToolName, "unknown")
	id := sanitizeToken(t.CallID, "none")
	status := sanitizeToken(t.Status, "ok")
	summary := sanitizeSingleLine(t.Summary)
	if summary == "" {
		summary = status
	}
	return fmt.Sprintf("[tool_outcome] tool=%s id=%s status=%s summary=%s", name, id, status, summary)
}

// SummarizeToolOutcome produces a 1-line argument-free outcome summary
// (`[tool_outcome] tool=<name> id=<callID> status=<ok|error> summary=...`)
// suitable for episodic/session memory without persisting raw tool arguments.
func SummarizeToolOutcome(toolName, callID string, isError bool, rawPreview string, maxLen int) string {
	return NewToolOutcomeSummary(toolName, callID, isError, rawPreview, maxLen).String()
}

func sanitizeSingleLine(s string) string {
	if s == "" {
		return ""
	}
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

func sanitizeToken(s, fallback string) string {
	cleaned := sanitizeSingleLine(s)
	if cleaned == "" {
		return fallback
	}
	return strings.ReplaceAll(cleaned, " ", "_")
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 || s == "" {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	if maxRunes <= 3 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-3]) + "..."
}
