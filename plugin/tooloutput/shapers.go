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

var (
	searchLineRe = regexp.MustCompile(`^[^\s:][^:]*:\d+(:|$)`)
	lockfileRe   = regexp.MustCompile(`(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.sum|Cargo\.lock|poetry\.lock|Gemfile\.lock|composer\.lock)$`)

	defaultShaperRegistry = NewDefaultShaperRegistry()

	_ ContentShaper = (*jsonOutputShaper)(nil)
	_ ContentShaper = (*diffOutputShaper)(nil)
	_ ContentShaper = (*searchOutputShaper)(nil)
	_ ContentShaper = (*codeOutputShaper)(nil)
	_ ContentShaper = (*logOutputShaper)(nil)
)

// ShaperRegistry orders ContentShapers and selects the first matching shaper
// for a given tool output payload.
type ShaperRegistry struct {
	shapers []ContentShaper
}

// NewShaperRegistry constructs a ShaperRegistry from an ordered list of ContentShapers.
func NewShaperRegistry(shapers ...ContentShaper) *ShaperRegistry {
	reg := &ShaperRegistry{}
	for _, s := range shapers {
		if s != nil {
			reg.shapers = append(reg.shapers, s)
		}
	}
	return reg
}

// NewDefaultShaperRegistry constructs a ShaperRegistry with the built-in JSON,
// diff, search, code, and fallback log shapers.
func NewDefaultShaperRegistry() *ShaperRegistry {
	return NewShaperRegistry(
		&jsonOutputShaper{},
		&diffOutputShaper{},
		&searchOutputShaper{},
		&codeOutputShaper{},
		&logOutputShaper{},
	)
}

// Register adds shaper ahead of any catch-all ContentLog shaper so custom
// structured shapers take priority over unstructured log clamping.
func (r *ShaperRegistry) Register(shaper ContentShaper) {
	if r == nil || shaper == nil {
		return
	}
	if len(r.shapers) > 0 && r.shapers[len(r.shapers)-1].ContentType() == ContentLog {
		last := r.shapers[len(r.shapers)-1]
		r.shapers[len(r.shapers)-1] = shaper
		r.shapers = append(r.shapers, last)
		return
	}
	r.shapers = append(r.shapers, shaper)
}

func (r *ShaperRegistry) match(text string) ContentShaper {
	if strings.TrimSpace(text) == "" {
		return &logOutputShaper{}
	}
	if r != nil {
		for _, s := range r.shapers {
			if s.CanShape(text) {
				return s
			}
		}
	}
	return &logOutputShaper{}
}

// DetectContentType returns the ContentType of the first matching shaper.
func (r *ShaperRegistry) DetectContentType(text string) ContentType {
	return r.match(text).ContentType()
}

// ShapeResult deterministically compacts text to fit within maxChars, returning
// the shaped text, detected ContentType, and whether compaction was applied.
func (r *ShaperRegistry) ShapeResult(text string, maxChars int, focus string) ShapeResult {
	if maxChars <= 0 {
		maxChars = DefaultMaxChars
	}
	shaper := r.match(text)
	if len(text) <= maxChars && strings.TrimSpace(focus) == "" {
		return ShapeResult{
			Content:     text,
			ContentType: shaper.ContentType(),
			Changed:     false,
		}
	}
	out := shaper.Shape(text, maxChars, focus)
	if len(out) > maxChars {
		out = clampHeadTail(out, maxChars)
	}
	return ShapeResult{
		Content:     out,
		ContentType: shaper.ContentType(),
		Changed:     true,
	}
}

// Shape deterministically compacts text using r and returns (shaped, changed).
func (r *ShaperRegistry) Shape(text string, maxChars int, focus string) (string, bool) {
	res := r.ShapeResult(text, maxChars, focus)
	return res.Content, res.Changed
}

// DetectContentType deterministically classifies tool output using the default ShaperRegistry.
func DetectContentType(text string) ContentType {
	return defaultShaperRegistry.DetectContentType(text)
}

// Shape deterministically compacts text to fit within maxChars using the default ShaperRegistry.
func Shape(text string, maxChars int, focus string) (string, bool) {
	return defaultShaperRegistry.Shape(text, maxChars, focus)
}

// jsonOutputShaper compacts JSON objects and arrays while preserving outliers and focused items.
type jsonOutputShaper struct{}

func (s *jsonOutputShaper) ContentType() ContentType { return ContentJSON }

func (s *jsonOutputShaper) CanShape(text string) bool {
	trimmed := strings.TrimSpace(text)
	return (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) && json.Valid([]byte(trimmed))
}

func (s *jsonOutputShaper) Shape(text string, maxChars int, focus string) string {
	var parsed any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return (&logOutputShaper{}).Shape(text, maxChars, focus)
	}
	compacted := compactJSONValue(parsed, focus, 0)
	b, err := json.MarshalIndent(compacted, "", "  ")
	if err != nil {
		return (&logOutputShaper{}).Shape(text, maxChars, focus)
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

// diffOutputShaper compacts unified git diffs by summarizing lockfiles and unfocused sections.
type diffOutputShaper struct{}

func (s *diffOutputShaper) ContentType() ContentType { return ContentDiff }

func (s *diffOutputShaper) CanShape(text string) bool {
	trimmed := strings.TrimSpace(text)
	return strings.HasPrefix(trimmed, "diff --git ") ||
		strings.Contains(trimmed, "\ndiff --git ") ||
		(strings.Contains(trimmed, "\n--- ") && strings.Contains(trimmed, "\n+++ ") && strings.Contains(trimmed, "\n@@ "))
}

func (s *diffOutputShaper) Shape(text string, maxChars int, focus string) string {
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

// searchOutputShaper groups file:line search matches by file path.
type searchOutputShaper struct{}

func (s *searchOutputShaper) ContentType() ContentType { return ContentSearch }

func (s *searchOutputShaper) CanShape(text string) bool {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	nonEmpty := 0
	searchMatches := 0
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
	}
	return nonEmpty > 0 && searchMatches*2 >= nonEmpty
}

func (s *searchOutputShaper) Shape(text string, maxChars int, focus string) string {
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

// codeOutputShaper collapses deeply nested brace blocks while preserving top-level declarations.
type codeOutputShaper struct{}

func (s *codeOutputShaper) ContentType() ContentType { return ContentCode }

func (s *codeOutputShaper) CanShape(text string) bool {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	nonEmpty := 0
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
		if strings.HasPrefix(l, "func ") || strings.HasPrefix(l, "package ") ||
			strings.HasPrefix(l, "import ") || strings.HasPrefix(l, "def ") ||
			strings.HasPrefix(l, "class ") || strings.HasPrefix(l, "function ") ||
			strings.HasSuffix(l, "{") || l == "}" {
			codeHints++
		}
	}
	return nonEmpty > 0 && codeHints*4 >= nonEmpty
}

func (s *codeOutputShaper) Shape(text string, maxChars int, focus string) string {
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

// logOutputShaper is the fallback ContentShaper for unstructured logs and plain text.
type logOutputShaper struct{}

func (s *logOutputShaper) ContentType() ContentType { return ContentLog }

func (s *logOutputShaper) CanShape(_ string) bool { return true }

func (s *logOutputShaper) Shape(text string, maxChars int, focus string) string {
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
