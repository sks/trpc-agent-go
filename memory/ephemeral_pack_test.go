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
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryCitation_FormatCitationTag(t *testing.T) {
	ts := time.Date(2026, 5, 10, 12, 30, 0, 0, time.UTC)
	c := MemoryCitation{
		SourceID:  "mem-123",
		Category:  "episode",
		UpdatedAt: ts,
		Score:     0.91,
		Snippet:   "Deployed service to production",
	}
	assert.Equal(t, "[mem-123|episode|2026-05-10T12:30:00Z]", c.FormatCitationTag())

	empty := MemoryCitation{}
	assert.Equal(t, "[unknown|fact|unknown]", empty.FormatCitationTag())
}

func TestEphemeralPackBuilder_Build(t *testing.T) {
	ts1 := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	ts2 := time.Date(2026, 5, 11, 15, 30, 0, 0, time.UTC)

	t.Run("empty citations returns empty string", func(t *testing.T) {
		builder := NewEphemeralPackBuilder(256, 0)
		assert.Empty(t, builder.Build(nil))
		assert.Empty(t, builder.Build([]MemoryCitation{{Snippet: "   "}}))
	})

	t.Run("formats citations into xml memory-context block", func(t *testing.T) {
		builder := NewEphemeralPackBuilder(256, 0)
		pack := builder.Build([]MemoryCitation{
			{
				SourceID:  "src-1",
				Category:  "fact",
				UpdatedAt: ts1,
				Score:     0.95,
				Snippet:   "User prefers dark mode\nand concise diffs.",
			},
			{
				SourceID:  "src-2",
				Category:  "episode",
				UpdatedAt: ts2,
				Score:     0.82,
				Snippet:   "Resolved database migration lock.",
			},
		})

		require.NotEmpty(t, pack)
		assert.True(t, strings.HasPrefix(pack, "<memory-context>\n"))
		assert.True(t, strings.HasSuffix(pack, "\n</memory-context>"))
		assert.Contains(t, pack, "- [src-1|fact|2026-05-10T12:00:00Z] User prefers dark mode and concise diffs.")
		assert.Contains(t, pack, "- [src-2|episode|2026-05-11T15:30:00Z] Resolved database migration lock.")
	})

	t.Run("enforces MaxChars budget and truncates long snippets", func(t *testing.T) {
		builder := &EphemeralPackBuilder{MaxChars: 75}
		pack := builder.Build([]MemoryCitation{
			{
				SourceID:  "src-1",
				Category:  "fact",
				UpdatedAt: ts1,
				Snippet:   "This is a very long memory snippet that exceeds the character budget easily.",
			},
			{
				SourceID:  "src-2",
				Category:  "fact",
				UpdatedAt: ts2,
				Snippet:   "Second entry should not fit.",
			},
		})

		require.NotEmpty(t, pack)
		assert.Contains(t, pack, "[src-1|fact|2026-05-10T12:00:00Z]")
		assert.Contains(t, pack, "...")
		assert.NotContains(t, pack, "src-2")

		inner := strings.TrimSuffix(strings.TrimPrefix(pack, "<memory-context>\n"), "\n</memory-context>")
		assert.LessOrEqual(t, utf8.RuneCountInString(inner), 75)
	})

	t.Run("enforces MaxTokens budget when MaxChars is unset", func(t *testing.T) {
		builder := &EphemeralPackBuilder{MaxTokens: 15} // 60 chars
		pack := builder.Build([]MemoryCitation{
			{
				SourceID:  "m1",
				Category:  "fact",
				UpdatedAt: ts1,
				Snippet:   "Short snippet that will be truncated to fit token budget.",
			},
		})
		require.NotEmpty(t, pack)
		inner := strings.TrimSuffix(strings.TrimPrefix(pack, "<memory-context>\n"), "\n</memory-context>")
		assert.LessOrEqual(t, utf8.RuneCountInString(inner), 15*DefaultCharsPerToken)
	})

	t.Run("builds from memory entries", func(t *testing.T) {
		entries := []*Entry{
			nil,
			{ID: "empty-mem", Memory: &Memory{Memory: "   "}},
			{
				ID:        "e-1",
				UpdatedAt: ts1,
				Score:     0.88,
				Memory: &Memory{
					Memory: "Cluster runs in us-west-2",
					Kind:   KindFact,
				},
			},
		}
		builder := NewEphemeralPackBuilder(128, 0)
		pack := builder.BuildEntries(entries)
		assert.Contains(t, pack, "- [e-1|fact|2026-05-10T12:00:00Z] Cluster runs in us-west-2")
	})
}

func TestSummarizeToolOutcome(t *testing.T) {
	t.Run("formats 1-line ok outcome without arguments and collapses newlines", func(t *testing.T) {
		got := SummarizeToolOutcome("kubectl_get", "call-42", false, "3 pods running\nin namespace prod", 80)
		assert.Equal(t, "[tool_outcome] tool=kubectl_get id=call-42 status=ok summary=3 pods running in namespace prod", got)
		assert.NotContains(t, got, "\n")
	})

	t.Run("formats error outcome and truncates to maxLen", func(t *testing.T) {
		longErr := "connection refused while dialing tcp 10.0.0.1:5432 with very verbose stack trace details"
		got := SummarizeToolOutcome("pg_query", "call-99", true, longErr, 32)
		assert.True(t, strings.HasPrefix(got, "[tool_outcome] tool=pg_query id=call-99 status=error summary="))
		assert.True(t, strings.HasSuffix(got, "..."))
		assert.NotContains(t, got, "\n")

		summaryObj := NewToolOutcomeSummary("pg_query", "call-99", true, longErr, 32)
		assert.LessOrEqual(t, utf8.RuneCountInString(summaryObj.Summary), 32)
		assert.Equal(t, "error", summaryObj.Status)
	})

	t.Run("handles empty fields with safe defaults", func(t *testing.T) {
		got := SummarizeToolOutcome("", "", false, "   ", 0)
		assert.Equal(t, "[tool_outcome] tool=unknown id=none status=ok summary=ok", got)
	})

	t.Run("PackFormatter and OutcomeSummarizer interfaces work via structs and wrappers", func(t *testing.T) {
		var formatter PackFormatter = NewEphemeralPackBuilder(128, 0)
		ts := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
		entries := []*Entry{{
			ID:        "mem-9",
			UpdatedAt: ts,
			Memory:    &Memory{Memory: "Prefers structured Go interfaces", Kind: KindFact},
		}}
		assert.Equal(t, formatter.BuildEntries(entries), BuildEphemeralPack(entries, 128, 0))

		var summarizer OutcomeSummarizer = NewDefaultOutcomeSummarizer(40)
		structured := summarizer.Summarize("git_status", "c-1", false, "clean working tree")
		assert.Equal(t, "ok", structured.Status)
		assert.Equal(t, structured.String(), summarizer.Format("git_status", "c-1", false, "clean working tree"))
	})
}
