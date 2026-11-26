//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
// trpc-agent-go is licensed under the Apache License Version 2.0.
//
//

package toolsearch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"trpc.group/trpc-go/trpc-agent-go/tool"
)

// ComputeToolContentHash computes a deterministic SHA-256 content hash over:
//
//	name + "\x00" + description + "\x00" + schema_json
//
// Repeated indexing / startup uses this digest to skip re-embedding tools whose
// name, description, and input schema have not changed.
func ComputeToolContentHash(t tool.Tool) string {
	if t == nil {
		return ""
	}
	return ComputeDeclarationContentHash(t.Declaration())
}

// ComputeDeclarationContentHash computes a deterministic SHA-256 content hash
// over decl.Name + "\x00" + decl.Description + "\x00" + schema_json.
func ComputeDeclarationContentHash(decl *tool.Declaration) string {
	if decl == nil {
		return ""
	}
	var schemaJSON string
	if decl.InputSchema != nil {
		data, err := json.Marshal(decl.InputSchema)
		if err == nil {
			schemaJSON = string(data)
		}
	}
	payload := decl.Name + "\x00" + decl.Description + "\x00" + schemaJSON
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// EmbeddingCache is a thread-safe, additive content-hash cache that maps a tool's
// SHA-256 content hash (and tool name) to its previously computed embedding
// vector. When a tool's content hash is unchanged across indexing passes or
// restarts, its cached vector is reused without invoking the remote embedder.
type EmbeddingCache struct {
	mu         sync.RWMutex
	byHash     map[string][]float64
	hashByTool map[string]string
	hits       int64
	misses     int64
}

// NewEmbeddingCache creates an empty EmbeddingCache.
func NewEmbeddingCache() *EmbeddingCache {
	return &EmbeddingCache{
		byHash:     make(map[string][]float64),
		hashByTool: make(map[string]string),
	}
}

// Lookup returns the cached embedding for contentHash if present.
func (c *EmbeddingCache) Lookup(contentHash string) ([]float64, bool) {
	if c == nil || contentHash == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	vec, ok := c.byHash[contentHash]
	if !ok {
		c.misses++
		return nil, false
	}
	c.hits++
	cp := make([]float64, len(vec))
	copy(cp, vec)
	return cp, true
}

// Store records an embedding for toolName and contentHash.
func (c *EmbeddingCache) Store(toolName, contentHash string, vec []float64) {
	if c == nil || contentHash == "" || len(vec) == 0 {
		return
	}
	cp := make([]float64, len(vec))
	copy(cp, vec)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byHash[contentHash] = cp
	if toolName != "" {
		c.hashByTool[toolName] = contentHash
	}
}

// IsUnchanged reports whether toolName is already cached with contentHash.
func (c *EmbeddingCache) IsUnchanged(toolName, contentHash string) bool {
	if c == nil || toolName == "" || contentHash == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	prev, ok := c.hashByTool[toolName]
	if !ok || prev != contentHash {
		return false
	}
	_, hasVec := c.byHash[contentHash]
	return hasVec
}

// Invalidate removes toolName's association from the cache. The underlying
// content-hash vector remains available if the exact declaration reappears.
func (c *EmbeddingCache) Invalidate(toolName string) {
	if c == nil || toolName == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.hashByTool, toolName)
}

// Stats returns the cumulative cache hits, misses, and number of unique hashes stored.
func (c *EmbeddingCache) Stats() (hits, misses int64, entries int) {
	if c == nil {
		return 0, 0, 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, len(c.byHash)
}

// ExtractToolFamily derives the logical family/namespace prefix from a tool name
// for two-stage family narrowing:
//   - "mcp__<server>__<tool>" -> "mcp__<server>"
//   - "<prefix>__<rest>"      -> "<prefix>"
//   - "<prefix>_<rest>"       -> "<prefix>"
//   - "<prefix>.<rest>"       -> "<prefix>"
//   - "<prefix>/<rest>"       -> "<prefix>"
//   - single token            -> lowercase toolName
func ExtractToolFamily(toolName string) string {
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
	// (return 0 tools). For semantic search scores are typically in [0, 1];
	// for keyword search scores are raw integer term weights (e.g. >= 3).
	MinScore float64

	// MinScoreGap requires the top candidate to exceed the Nth comparator
	// (second place, or first outside the winning family / top-K cutoff) by at
	// least MinScoreGap when the top score is below HighConfidenceFloor.
	// If HighConfidenceFloor is 0, a default floor of 0.85 (for normalized
	// scores <= 1.0) is used so unambiguous high-scoring matches are not
	// discarded when sister tools in the same family also score well.
	MinScoreGap float64

	// HighConfidenceFloor is the score above which MinScoreGap is bypassed.
	// When 0 and MinScoreGap > 0, defaults to 0.85 for normalized [0,1] scores.
	HighConfidenceFloor float64

	// RequireLexicalOverlap, when true, requires at least one non-stopword query
	// token (len >= 3) to appear in the top candidate's name, family, or
	// description unless the top candidate's score is >= HighConfidenceFloor.
	RequireLexicalOverlap bool

	// TopFamilies enables two-stage family/namespace narrowing when > 0:
	// Stage 1 groups candidates by ExtractToolFamily(name), ranks families by
	// their best candidate score (plus an optional family-token match bonus),
	// keeps the top TopFamilies families, and Stage 2 ranks tools within those
	// winning families.
	TopFamilies int
}

// ScoredCandidate pairs a tool name with its similarity/relevance score and
// optional metadata for two-stage family narrowing and abstention decisions.
type ScoredCandidate struct {
	Name        string
	Score       float64
	Description string
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

// NarrowByToolFamily performs Stage 1 of two-stage tool search: it groups
// candidates by ExtractToolFamily(name), scores each family by its strongest
// member (plus a small bonus when query tokens match the family name), keeps
// the top topFamilies families, and returns candidates belonging to those
// winning families in descending score order.
func NarrowByToolFamily(candidates []ScoredCandidate, queries []string, topFamilies int) []ScoredCandidate {
	if len(candidates) == 0 || topFamilies <= 0 {
		return candidates
	}

	queryTokens := significantQueryTokens(queries)

	type familyGroup struct {
		family   string
		maxScore float64
		members  []ScoredCandidate
	}
	groups := make(map[string]*familyGroup)
	order := make([]string, 0)
	for _, c := range candidates {
		fam := ExtractToolFamily(c.Name)
		g, ok := groups[fam]
		if !ok {
			g = &familyGroup{
				family:   fam,
				maxScore: c.Score,
			}
			groups[fam] = g
			order = append(order, fam)
		}
		if c.Score > g.maxScore {
			g.maxScore = c.Score
		}
		g.members = append(g.members, c)
	}

	if len(groups) <= topFamilies {
		return candidates
	}

	for _, g := range groups {
		for tok := range queryTokens {
			if strings.Contains(g.family, tok) {
				g.maxScore += 0.05
				break
			}
		}
	}

	sort.Slice(order, func(i, j int) bool {
		gi, gj := groups[order[i]], groups[order[j]]
		if gi.maxScore != gj.maxScore {
			return gi.maxScore > gj.maxScore
		}
		return gi.family < gj.family
	})

	winning := make(map[string]struct{}, topFamilies)
	for i := 0; i < topFamilies && i < len(order); i++ {
		winning[order[i]] = struct{}{}
	}

	narrowed := make([]ScoredCandidate, 0, len(candidates))
	for _, c := range candidates {
		if _, ok := winning[ExtractToolFamily(c.Name)]; ok {
			narrowed = append(narrowed, c)
		}
	}
	sort.Slice(narrowed, func(i, j int) bool {
		if narrowed[i].Score != narrowed[j].Score {
			return narrowed[i].Score > narrowed[j].Score
		}
		return narrowed[i].Name < narrowed[j].Name
	})
	return narrowed
}

// ApplyAbstention evaluates Stage 2 retrieve-then-decide abstention over sorted
// or unsorted candidates. It returns nil (0 tools) when:
//   - candidates is empty;
//   - the top candidate score is below cfg.MinScore;
//   - cfg.MinScoreGap > 0 and the score gap between the top candidate and the
//     comparator candidate (first candidate outside the top tool's family, or
//     second candidate if all share a family) is less than cfg.MinScoreGap
//     (unless top score >= highConfidenceFloor);
//   - cfg.RequireLexicalOverlap is true and no significant query token overlaps
//     the top candidate's name or description (unless top score >= highConfidenceFloor).
//
// Otherwise it returns the surviving candidates (filtering out individual hits
// below cfg.MinScore) sorted by descending score.
func ApplyAbstention(candidates []ScoredCandidate, queries []string, cfg *AbstentionConfig) []ScoredCandidate {
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

	if cfg == nil {
		return sorted
	}

	if cfg.TopFamilies > 0 {
		sorted = NarrowByToolFamily(sorted, queries, cfg.TopFamilies)
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
		topFamily := ExtractToolFamily(top.Name)
		// Prefer comparing against the strongest rival from a different family
		// when multiple families are present so sibling tools in the same MCP
		// server don't artificially zero out the score gap; fall back to rank-2
		// when all candidates share a family or rival family gap is still flat.
		for i := 1; i < len(sorted); i++ {
			if ExtractToolFamily(sorted[i].Name) != topFamily {
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
