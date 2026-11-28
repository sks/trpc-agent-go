//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
// trpc-agent-go is licensed under the Apache License Version 2.0.
//
//

package toolsearch

import (
	"sort"
	"strings"
)

const defaultFamilyMatchBonus = 0.05

// ScoredCandidate pairs a tool name with its similarity/relevance score and
// optional description for two-stage family narrowing and abstention decisions.
type ScoredCandidate struct {
	Name        string
	Score       float64
	Description string
}

// ToolFamilyScore represents a grouped family of candidate tools and its
// aggregate Stage 1 ranking score.
type ToolFamilyScore struct {
	Family   string
	MaxScore float64
	Members  []ScoredCandidate
}

// ToolFamilyExtractor derives logical family/namespace prefixes from tool names
// and performs Stage 1 family-level candidate narrowing.
type ToolFamilyExtractor interface {
	ExtractFamily(toolName string) string
	Narrow(candidates []ScoredCandidate, queries []string, topFamilies int) []ScoredCandidate
}

var _ ToolFamilyExtractor = DefaultFamilyExtractor{}

// DefaultFamilyExtractor extracts family prefixes using MCP, double-underscore,
// and standard separator conventions, applying an optional lexical query bonus.
type DefaultFamilyExtractor struct {
	// FamilyMatchBonus is added to a family's MaxScore when any significant query
	// token matches the family name. Non-positive values default to 0.05.
	FamilyMatchBonus float64
}

// NewDefaultFamilyExtractor returns a DefaultFamilyExtractor with the default match bonus.
func NewDefaultFamilyExtractor() DefaultFamilyExtractor {
	return DefaultFamilyExtractor{FamilyMatchBonus: defaultFamilyMatchBonus}
}

// ExtractFamily derives the logical family/namespace prefix from toolName:
//   - "mcp__<server>__<tool>" -> "mcp__<server>"
//   - "<prefix>__<rest>"      -> "<prefix>"
//   - "<prefix>_<rest>"       -> "<prefix>"
//   - "<prefix>.<rest>"       -> "<prefix>"
//   - "<prefix>/<rest>"       -> "<prefix>"
//   - single token            -> lowercase toolName
func (e DefaultFamilyExtractor) ExtractFamily(toolName string) string {
	trimmed := strings.TrimSpace(toolName)
	if trimmed == "" {
		return ""
	}
	lower := strings.ToLower(trimmed)
	if server, _, ok := parseMCPName(lower); ok {
		return mcpNamePrefix + server
	}
	if idx := strings.Index(lower, "__"); idx > 0 {
		return lower[:idx]
	}
	if idx := strings.IndexAny(lower, "_./:"); idx > 0 {
		return lower[:idx]
	}
	return lower
}

// RankFamilies groups candidates by family and returns them sorted by descending MaxScore.
func (e DefaultFamilyExtractor) RankFamilies(candidates []ScoredCandidate, queries []string) []ToolFamilyScore {
	if len(candidates) == 0 {
		return nil
	}
	bonus := e.FamilyMatchBonus
	if bonus <= 0 {
		bonus = defaultFamilyMatchBonus
	}
	queryTokens := significantQueryTokens(queries)

	groups := make(map[string]*ToolFamilyScore)
	order := make([]string, 0)
	for _, c := range candidates {
		fam := e.ExtractFamily(c.Name)
		g, ok := groups[fam]
		if !ok {
			g = &ToolFamilyScore{
				Family:   fam,
				MaxScore: c.Score,
			}
			groups[fam] = g
			order = append(order, fam)
		}
		if c.Score > g.MaxScore {
			g.MaxScore = c.Score
		}
		g.Members = append(g.Members, c)
	}

	for _, g := range groups {
		for tok := range queryTokens {
			if strings.Contains(g.Family, tok) {
				g.MaxScore += bonus
				break
			}
		}
	}

	ranked := make([]ToolFamilyScore, 0, len(order))
	for _, fam := range order {
		ranked = append(ranked, *groups[fam])
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].MaxScore != ranked[j].MaxScore {
			return ranked[i].MaxScore > ranked[j].MaxScore
		}
		return ranked[i].Family < ranked[j].Family
	})
	return ranked
}

// Narrow keeps candidates belonging to the top topFamilies ranked families,
// sorted by descending candidate score.
func (e DefaultFamilyExtractor) Narrow(candidates []ScoredCandidate, queries []string, topFamilies int) []ScoredCandidate {
	if len(candidates) == 0 || topFamilies <= 0 {
		return candidates
	}
	rankedFamilies := e.RankFamilies(candidates, queries)
	if len(rankedFamilies) <= topFamilies {
		return candidates
	}

	winning := make(map[string]struct{}, topFamilies)
	for i := 0; i < topFamilies && i < len(rankedFamilies); i++ {
		winning[rankedFamilies[i].Family] = struct{}{}
	}

	narrowed := make([]ScoredCandidate, 0, len(candidates))
	for _, c := range candidates {
		if _, ok := winning[e.ExtractFamily(c.Name)]; ok {
			narrowed = append(narrowed, c)
		}
	}
	return sortScoredCandidates(narrowed)
}

// ExtractToolFamily derives the logical family/namespace prefix from toolName
// using DefaultFamilyExtractor.
func ExtractToolFamily(toolName string) string {
	return DefaultFamilyExtractor{}.ExtractFamily(toolName)
}

// NarrowByToolFamily performs Stage 1 of two-stage tool search using DefaultFamilyExtractor.
func NarrowByToolFamily(candidates []ScoredCandidate, queries []string, topFamilies int) []ScoredCandidate {
	return NewDefaultFamilyExtractor().Narrow(candidates, queries, topFamilies)
}

func sortScoredCandidates(candidates []ScoredCandidate) []ScoredCandidate {
	if len(candidates) == 0 {
		return nil
	}
	sorted := make([]ScoredCandidate, len(candidates))
	copy(sorted, candidates)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Score != sorted[j].Score {
			return sorted[i].Score > sorted[j].Score
		}
		return sorted[i].Name < sorted[j].Name
	})
	return sorted
}
