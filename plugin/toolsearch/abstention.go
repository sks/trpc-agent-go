//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
// trpc-agent-go is licensed under the Apache License Version 2.0.
//
//

package toolsearch

import "strings"

// AbstentionDecider evaluates Stage 2 retrieve-then-decide abstention over
// scored tool candidates so non-matching queries return 0 tools instead of
// top-K false positives.
type AbstentionDecider interface {
	ShouldAbstain(candidates []ScoredCandidate, queries []string) bool
	ApplyAbstention(candidates []ScoredCandidate, queries []string) []ScoredCandidate
}

var (
	_ AbstentionDecider = AbstentionConfig{}
	_ AbstentionDecider = (*AbstentionConfig)(nil)
)

// AbstentionConfig controls score-gap and minimum-confidence abstention as well
// as optional lexical-overlap gating and two-stage family narrowing.
//
// When configured on a Plugin (via WithAbstentionConfig) or SemanticToolIndex
// (via WithSemanticAbstentionConfig), queries that fail the confidence floor
// or score-gap / lexical gate return 0 tools (nil/empty slice) instead of
// top-K false positives.
type AbstentionConfig struct {
	// MinScore is the minimum similarity / relevance score required for the
	// top candidate. Queries whose top candidate scores below MinScore abstain
	// (return 0 tools).
	MinScore float64

	// MinScoreGap requires the top candidate to exceed the comparator candidate
	// (first outside the winning family, or rank-2 if all share a family) by at
	// least MinScoreGap when the top score is below HighConfidenceFloor.
	MinScoreGap float64

	// HighConfidenceFloor is the score above which MinScoreGap and
	// RequireLexicalOverlap are bypassed. When 0 and scores are normalized
	// (<= 1.0), defaults to 0.85.
	HighConfidenceFloor float64

	// RequireLexicalOverlap, when true, requires at least one non-stopword query
	// token (len >= 3) to appear in the top candidate's name or description
	// unless the top candidate's score is >= HighConfidenceFloor.
	RequireLexicalOverlap bool

	// TopFamilies enables two-stage family/namespace narrowing when > 0.
	TopFamilies int

	// FamilyExtractor optionally customizes Stage 1 family extraction and narrowing.
	// When nil, DefaultFamilyExtractor is used.
	FamilyExtractor ToolFamilyExtractor
}

func (cfg AbstentionConfig) familyExtractor() ToolFamilyExtractor {
	if cfg.FamilyExtractor != nil {
		return cfg.FamilyExtractor
	}
	return NewDefaultFamilyExtractor()
}

// ShouldAbstain reports whether the candidate set fails confidence, score-gap,
// or lexical-overlap gates and should return 0 tools.
func (cfg AbstentionConfig) ShouldAbstain(candidates []ScoredCandidate, queries []string) bool {
	return len(cfg.ApplyAbstention(candidates, queries)) == 0
}

// ApplyAbstention evaluates Stage 2 retrieve-then-decide abstention over
// candidates and returns the surviving candidates sorted by descending score,
// or nil when the query should abstain.
func (cfg AbstentionConfig) ApplyAbstention(candidates []ScoredCandidate, queries []string) []ScoredCandidate {
	sorted := sortScoredCandidates(candidates)
	if len(sorted) == 0 {
		return nil
	}

	extractor := cfg.familyExtractor()
	if cfg.TopFamilies > 0 {
		sorted = extractor.Narrow(sorted, queries, cfg.TopFamilies)
		if len(sorted) == 0 {
			return nil
		}
	}

	top := sorted[0]
	if cfg.MinScore > 0 && top.Score < cfg.MinScore {
		return nil
	}

	highFloor := cfg.HighConfidenceFloor
	if highFloor <= 0 && top.Score <= 1.0 {
		highFloor = 0.85
	}

	if cfg.MinScoreGap > 0 && len(sorted) > 1 && (highFloor <= 0 || top.Score < highFloor) {
		comparatorScore := sorted[1].Score
		topFamily := extractor.ExtractFamily(top.Name)
		// Compare against the strongest rival from a different family when multiple
		// families exist so sibling tools in the same server don't artificially zero out the gap.
		for i := 1; i < len(sorted); i++ {
			if extractor.ExtractFamily(sorted[i].Name) != topFamily {
				comparatorScore = sorted[i].Score
				break
			}
		}
		if (top.Score - comparatorScore) < cfg.MinScoreGap {
			return nil
		}
	}

	if cfg.RequireLexicalOverlap && (highFloor <= 0 || top.Score < highFloor) {
		if !hasLexicalOverlap(top, queries) {
			return nil
		}
	}

	if cfg.MinScore <= 0 {
		return sorted
	}
	out := make([]ScoredCandidate, 0, len(sorted))
	for _, c := range sorted {
		if c.Score >= cfg.MinScore {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ApplyAbstention evaluates Stage 2 retrieve-then-decide abstention using cfg.
// When cfg is nil, candidates are returned sorted by descending score without abstaining.
func ApplyAbstention(candidates []ScoredCandidate, queries []string, cfg *AbstentionConfig) []ScoredCandidate {
	if len(candidates) == 0 {
		return nil
	}
	if cfg == nil {
		return sortScoredCandidates(candidates)
	}
	return cfg.ApplyAbstention(candidates, queries)
}

// conversationalStopwords are common conversational/chit-chat tokens that carry
// no tool-invocation intent on their own.
var conversationalStopwords = map[string]struct{}{
	"the": {}, "and": {}, "for": {}, "that": {}, "this": {}, "with": {},
	"from": {}, "have": {}, "what": {}, "when": {}, "where": {}, "which": {},
	"who": {}, "whom": {}, "whose": {}, "why": {}, "how": {}, "can": {},
	"could": {}, "would": {}, "should": {}, "will": {}, "shall": {}, "may": {},
	"might": {}, "must": {}, "you": {}, "your": {}, "yours": {}, "please": {},
	"thanks": {}, "thank": {}, "hello": {}, "hey": {}, "hi": {}, "good": {},
	"morning": {}, "afternoon": {}, "evening": {}, "there": {}, "are": {},
	"was": {}, "were": {}, "been": {}, "being": {}, "about": {}, "into": {},
	"just": {}, "like": {}, "know": {}, "think": {}, "tell": {}, "explain": {},
	"mean": {}, "does": {}, "did": {}, "doing": {}, "done": {}, "make": {},
	"some": {}, "more": {}, "very": {}, "much": {}, "many": {}, "also": {},
}

func significantQueryTokens(queries []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, q := range queries {
		for _, tok := range tokenizeQuery(q) {
			tok = strings.TrimPrefix(tok, "+")
			for _, sub := range splitRequiredTerm(tok) {
				if len(sub) < 3 {
					continue
				}
				if _, stop := conversationalStopwords[sub]; stop {
					continue
				}
				out[sub] = struct{}{}
			}
		}
	}
	return out
}

func hasLexicalOverlap(c ScoredCandidate, queries []string) bool {
	qTokens := significantQueryTokens(queries)
	if len(qTokens) == 0 {
		return false
	}
	haystack := strings.ToLower(c.Name + " " + c.Description)
	for tok := range qTokens {
		if strings.Contains(haystack, tok) {
			return true
		}
	}
	return false
}
