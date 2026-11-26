//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package tooloutput

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ContentType identifies the detected structure of a tool output.
type ContentType string

const (
	ContentJSON   ContentType = "json"
	ContentDiff   ContentType = "diff"
	ContentSearch ContentType = "search"
	ContentCode   ContentType = "code"
	ContentLog    ContentType = "log"
)

var (
	searchLineRe = regexp.MustCompile(`^[^\s:][^:]*:\d+(:|$)`)
	lockfileRe   = regexp.MustCompile(`(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.sum|Cargo\.lock|poetry\.lock|Gemfile\.lock|composer\.lock)$`)
)

// DetectContentType deterministically classifies tool output.
func DetectContentType(text string) ContentType {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return ContentLog
	}
	if (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) && json.Valid([]byte(trimmed)) {
		return ContentJSON
	}
	if strings.HasPrefix(trimmed, "diff --git ") ||
		strings.Contains(trimmed, "\ndiff --git ") ||
		(strings.Contains(trimmed, "\n--- ") && strings.Contains(trimmed, "\n+++ ") && strings.Contains(trimmed, "\n@@ ")) {
		return ContentDiff
	}

	lines := strings.Split(trimmed, "\n")
	nonEmpty := 0
	searchMatches := 0
	codeHints := 0
	for i, line := range lines {
		if i >= 60 {
			break
		}
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		nonEmpty++
		if searchLineRe.MatchString(l) {
			searchMatches++
		}
		if strings.HasPrefix(l, "func ") || strings.HasPrefix(l, "package ") ||
			strings.HasPrefix(l, "import ") || strings.HasPrefix(l, "def ") ||
			strings.HasPrefix(l, "class ") || strings.HasPrefix(l, "function ") ||
			strings.HasSuffix(l, "{") || l == "}" {
			codeHints++
		}
	}
	if nonEmpty > 0 && searchMatches*2 >= nonEmpty {
		return ContentSearch
	}
	if nonEmpty > 0 && codeHints*4 >= nonEmpty {
		return ContentCode
	}
	return ContentLog
}

// Shape deterministically compacts text to fit within maxChars, optionally
// prioritizing lines/items matching focus.
func Shape(text string, maxChars int, focus string) (string, bool) {
	if maxChars <= 0 {
		maxChars = 6000
	}
	if len(text) <= maxChars && strings.TrimSpace(focus) == "" {
		return text, false
	}

	var out string
	switch DetectContentType(text) {
	case ContentJSON:
		out = shapeJSON(text, maxChars, focus)
	case ContentDiff:
		out = shapeDiff(text, maxChars, focus)
	case ContentSearch:
		out = shapeSearch(text, maxChars, focus)
	case ContentCode:
		out = shapeCode(text, maxChars, focus)
	default:
		out = shapeLog(text, maxChars, focus)
	}
	if len(out) > maxChars {
		out = clampHeadTail(out, maxChars)
	}
	return out, true
}

func shapeJSON(text string, maxChars int, focus string) string {
	var parsed any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return shapeLog(text, maxChars, focus)
	}
	compacted := compactJSONValue(parsed, focus, 0)
	b, err := json.MarshalIndent(compacted, "", "  ")
	if err != nil {
		return shapeLog(text, maxChars, focus)
	}
	if len(b) <= maxChars {
		return string(b)
	}
	return clampHeadTail(string(b), maxChars)
}

func compactJSONValue(v any, focus string, depth int) any {
	switch val := v.(type) {
	case []any:
		if len(val) <= 5 {
			out := make([]any, len(val))
			for i, item := range val {
				out[i] = compactJSONValue(item, focus, depth+1)
			}
			return out
		}
		kept := make([]any, 0, 8)
		for i, item := range val {
			if i < 3 || isOutlierOrFocused(item, focus) {
				kept = append(kept, compactJSONValue(item, focus, depth+1))
				if len(kept) >= 8 {
					break
				}
			}
		}
		if len(kept) < len(val) {
			kept = append(kept, fmt.Sprintf("... %d more items ...", len(val)-len(kept)))
		}
		return kept
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			out[k] = compactJSONValue(item, focus, depth+1)
		}
		return out
	default:
		return v
	}
}

func isOutlierOrFocused(item any, focus string) bool {
	b, err := json.Marshal(item)
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(b))
	if focus != "" && strings.Contains(lower, strings.ToLower(focus)) {
		return true
	}
	for _, kw := range []string{`"error"`, `"err"`, `"failed"`, `"exception"`, `"fatal"`, `"panic"`} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func shapeDiff(text string, maxChars int, focus string) string {
	sections := strings.Split(text, "\ndiff --git ")
	var b strings.Builder
	for i, sec := range sections {
		if i > 0 {
			sec = "diff --git " + sec
		}
		lines := strings.Split(sec, "\n")
		header := lines[0]
		filePath := extractDiffPath(header)
		if lockfileRe.MatchString(filePath) {
			added, removed := countDiffLines(lines)
			fmt.Fprintf(&b, "%s: +%d/-%d lines (lockfile compacted)\n", filePath, added, removed)
			continue
		}
		if focus != "" && !strings.Contains(strings.ToLower(sec), strings.ToLower(focus)) {
			added, removed := countDiffLines(lines)
			fmt.Fprintf(&b, "%s: +%d/-%d lines (omitted, no focus match)\n", filePath, added, removed)
			continue
		}
		b.WriteString(sec)
		if !strings.HasSuffix(sec, "\n") {
			b.WriteByte('\n')
		}
		if b.Len() >= maxChars {
			break
		}
	}
	return b.String()
}

func extractDiffPath(header string) string {
	fields := strings.Fields(header)
	if len(fields) >= 4 {
		return strings.TrimPrefix(fields[3], "b/")
	}
	return header
}

func countDiffLines(lines []string) (int, int) {
	var added, removed int
	for _, l := range lines {
		if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") {
			added++
		} else if strings.HasPrefix(l, "-") && !strings.HasPrefix(l, "---") {
			removed++
		}
	}
	return added, removed
}

func shapeSearch(text string, maxChars int, focus string) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	type group struct {
		path  string
		lines []string
	}
	var order []string
	groups := make(map[string]*group)
	for _, line := range lines {
		if focus != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(focus)) {
			continue
		}
		path := line
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			path = line[:idx]
		}
		g, ok := groups[path]
		if !ok {
			g = &group{path: path}
			groups[path] = g
			order = append(order, path)
		}
		g.lines = append(g.lines, line)
	}
	var b strings.Builder
	const maxPerFile = 3
	for _, path := range order {
		g := groups[path]
		limit := len(g.lines)
		if limit > maxPerFile {
			limit = maxPerFile
		}
		for i := 0; i < limit; i++ {
			b.WriteString(g.lines[i])
			b.WriteByte('\n')
		}
		if len(g.lines) > maxPerFile {
			fmt.Fprintf(&b, "  [+%d more matches in %s]\n", len(g.lines)-maxPerFile, path)
		}
		if b.Len() >= maxChars {
			break
		}
	}
	return b.String()
}

func shapeCode(text string, maxChars int, focus string) string {
	lines := strings.Split(text, "\n")
	var b strings.Builder
	depth := 0
	collapsed := 0
	focusLower := strings.ToLower(focus)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		opens := strings.Count(line, "{")
		closes := strings.Count(line, "}")
		nextDepth := depth + opens - closes
		if nextDepth < 0 {
			nextDepth = 0
		}

		inDeepBody := depth >= 2 && (focus == "" || !strings.Contains(strings.ToLower(line), focusLower))
		if inDeepBody && nextDepth >= 2 {
			collapsed++
			depth = nextDepth
			continue
		}
		if collapsed > 0 {
			fmt.Fprintf(&b, "    ... %d lines ...\n", collapsed)
			collapsed = 0
		}
		if trimmed != "" || b.Len() > 0 {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		depth = nextDepth
		if b.Len() >= maxChars {
			break
		}
	}
	if collapsed > 0 {
		fmt.Fprintf(&b, "    ... %d lines ...\n", collapsed)
	}
	return b.String()
}

func shapeLog(text string, maxChars int, focus string) string {
	if focus != "" {
		lines := strings.Split(text, "\n")
		var matched []string
		focusLower := strings.ToLower(focus)
		for _, l := range lines {
			if strings.Contains(strings.ToLower(l), focusLower) {
				matched = append(matched, l)
			}
		}
		if len(matched) > 0 {
			joined := strings.Join(matched, "\n")
			if len(joined) <= maxChars {
				return joined
			}
			return clampHeadTail(joined, maxChars)
		}
	}
	return clampHeadTail(text, maxChars)
}

func clampHeadTail(text string, maxChars int) string {
	if len(text) <= maxChars {
		return text
	}
	if maxChars < 80 {
		return text[:maxChars]
	}
	headLen := maxChars / 2
	tailLen := maxChars - headLen - 40
	if tailLen < 0 {
		tailLen = 0
	}
	omitted := len(text) - headLen - tailLen
	return fmt.Sprintf("%s\n... [%d chars omitted] ...\n%s", text[:headLen], omitted, text[len(text)-tailLen:])
}
