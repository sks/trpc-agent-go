//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package tooloutput

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/tidwall/gjson"
	"golang.org/x/net/html"

	"trpc.group/trpc-go/trpc-agent-go/tool"
	"trpc.group/trpc-go/trpc-agent-go/tool/function"
)

// RetrieveArgs defines arguments for tool_result_retrieve.
type RetrieveArgs struct {
	Handle string `json:"handle" jsonschema:"description=The ⟦ccr:...⟧ handle or SHA-256 hash of the stored tool output."`
	Mode   string `json:"mode,omitempty" jsonschema:"description=Slice mode: 'lines' (default) or 'bytes'."`
	Offset int    `json:"offset,omitempty" jsonschema:"description=0-based start line or byte offset."`
	Limit  int    `json:"limit,omitempty" jsonschema:"description=Maximum number of lines or bytes to return (default 100 lines or 4000 bytes)."`
}

// RetrieveResult is returned by tool_result_retrieve.
type RetrieveResult struct {
	Handle    string `json:"handle"`
	Mode      string `json:"mode"`
	Offset    int    `json:"offset"`
	Total     int    `json:"total"`
	Returned  int    `json:"returned"`
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
}

// QueryArgs defines arguments for tool_result_query.
type QueryArgs struct {
	Handle string `json:"handle" jsonschema:"description=The ⟦ccr:...⟧ handle or SHA-256 hash of the stored tool output."`
	Mode   string `json:"mode" jsonschema:"description=Query mode: 'regex', 'json', 'html', or 'bm25'."`
	Query  string `json:"query" jsonschema:"description=Regex pattern, gjson path, optional HTML filter, or BM25 search query."`
	Limit  int    `json:"limit,omitempty" jsonschema:"description=Maximum number of matches or blocks to return (default 20)."`
}

// QueryResult is returned by tool_result_query.
type QueryResult struct {
	Handle  string   `json:"handle"`
	Mode    string   `json:"mode"`
	Matches []string `json:"matches"`
	Count   int      `json:"count"`
}

// NewTools returns both zero-LLM CCR inspection tools bound to store.
func NewTools(store *CCRStore) []tool.Tool {
	return []tool.Tool{
		NewRetrieveTool(store),
		NewQueryTool(store),
	}
}

// NewRetrieveTool creates the tool_result_retrieve tool.
func NewRetrieveTool(store *CCRStore) tool.CallableTool {
	return function.NewFunctionTool(
		func(_ context.Context, args RetrieveArgs) (RetrieveResult, error) {
			content, ok := store.Get(args.Handle)
			if !ok {
				return RetrieveResult{}, fmt.Errorf("ccr handle not found: %s", args.Handle)
			}
			mode := strings.ToLower(strings.TrimSpace(args.Mode))
			if mode == "" {
				mode = "lines"
			}
			offset := args.Offset
			if offset < 0 {
				offset = 0
			}
			if mode == "bytes" {
				limit := args.Limit
				if limit <= 0 {
					limit = 4000
				}
				total := len(content)
				if offset >= total {
					return RetrieveResult{Handle: args.Handle, Mode: mode, Offset: offset, Total: total}, nil
				}
				end := offset + limit
				if end > total {
					end = total
				}
				slice := content[offset:end]
				return RetrieveResult{
					Handle:    args.Handle,
					Mode:      mode,
					Offset:    offset,
					Total:     total,
					Returned:  len(slice),
					Content:   slice,
					Truncated: end < total,
				}, nil
			}

			lines := strings.Split(content, "\n")
			limit := args.Limit
			if limit <= 0 {
				limit = 100
			}
			total := len(lines)
			if offset >= total {
				return RetrieveResult{Handle: args.Handle, Mode: "lines", Offset: offset, Total: total}, nil
			}
			end := offset + limit
			if end > total {
				end = total
			}
			slice := strings.Join(lines[offset:end], "\n")
			return RetrieveResult{
				Handle:    args.Handle,
				Mode:      "lines",
				Offset:    offset,
				Total:     total,
				Returned:  end - offset,
				Content:   slice,
				Truncated: end < total,
			}, nil
		},
		function.WithName("tool_result_retrieve"),
		function.WithDescription("Retrieve a byte or line range from a compacted tool output stored in CCR using its ⟦ccr:...⟧ handle."),
	)
}

// NewQueryTool creates the tool_result_query tool.
func NewQueryTool(store *CCRStore) tool.CallableTool {
	return function.NewFunctionTool(
		func(_ context.Context, args QueryArgs) (QueryResult, error) {
			content, ok := store.Get(args.Handle)
			if !ok {
				return QueryResult{}, fmt.Errorf("ccr handle not found: %s", args.Handle)
			}
			limit := args.Limit
			if limit <= 0 {
				limit = 20
			}
			mode := strings.ToLower(strings.TrimSpace(args.Mode))
			var matches []string
			var err error
			switch mode {
			case "regex", "grep":
				matches, err = queryRegex(content, args.Query, limit)
			case "json", "gjson":
				matches = queryGJSON(content, args.Query, limit)
			case "html":
				matches, err = queryHTML(content, args.Query, limit)
			case "bm25":
				matches = queryBM25(content, args.Query, limit)
			default:
				return QueryResult{}, fmt.Errorf("unsupported query mode %q (use regex, json, html, or bm25)", args.Mode)
			}
			if err != nil {
				return QueryResult{}, err
			}
			return QueryResult{
				Handle:  args.Handle,
				Mode:    mode,
				Matches: matches,
				Count:   len(matches),
			}, nil
		},
		function.WithName("tool_result_query"),
		function.WithDescription("Query a compacted tool output stored in CCR without LLM calls using regex, json (gjson path), html (links/headings), or bm25 block ranking."),
	)
}

func queryRegex(content, pattern string, limit int) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}
	lines := strings.Split(content, "\n")
	var matches []string
	for i, line := range lines {
		if re.MatchString(line) {
			matches = append(matches, fmt.Sprintf("%d: %s", i+1, line))
			if len(matches) >= limit {
				break
			}
		}
	}
	return matches, nil
}

func queryGJSON(content, path string, limit int) []string {
	res := gjson.Get(content, path)
	if !res.Exists() {
		return nil
	}
	if res.IsArray() {
		var matches []string
		res.ForEach(func(_, v gjson.Result) bool {
			matches = append(matches, v.String())
			return len(matches) < limit
		})
		return matches
	}
	return []string{res.String()}
}

func queryHTML(content, filter string, limit int) ([]string, error) {
	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("html parse error: %w", err)
	}
	filterLower := strings.ToLower(strings.TrimSpace(filter))
	var matches []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if len(matches) >= limit {
			return
		}
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				href := ""
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						href = attr.Val
						break
					}
				}
				text := strings.TrimSpace(extractNodeText(n))
				entry := fmt.Sprintf("link: [%s](%s)", text, href)
				if filterLower == "" || strings.Contains(strings.ToLower(entry), filterLower) {
					matches = append(matches, entry)
				}
			case "h1", "h2", "h3", "h4", "h5", "h6":
				text := strings.TrimSpace(extractNodeText(n))
				entry := fmt.Sprintf("%s: %s", n.Data, text)
				if filterLower == "" || strings.Contains(strings.ToLower(entry), filterLower) {
					matches = append(matches, entry)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return matches, nil
}

func extractNodeText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var b strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		b.WriteString(extractNodeText(c))
	}
	return b.String()
}

func queryBM25(content, query string, limit int) []string {
	qTerms := tokenizeWords(query)
	if len(qTerms) == 0 {
		return nil
	}
	blocks := splitBlocks(content)
	if len(blocks) == 0 {
		return nil
	}

	type doc struct {
		text  string
		terms map[string]int
		len   int
	}
	docs := make([]doc, len(blocks))
	df := make(map[string]int)
	totalLen := 0
	for i, blk := range blocks {
		tokens := tokenizeWords(blk)
		tf := make(map[string]int, len(tokens))
		for _, tok := range tokens {
			tf[tok]++
		}
		for term := range tf {
			df[term]++
		}
		docs[i] = doc{text: blk, terms: tf, len: len(tokens)}
		totalLen += len(tokens)
	}
	avgDL := float64(totalLen) / float64(len(docs))
	if avgDL == 0 {
		avgDL = 1
	}

	const k1 = 1.5
	const b = 0.75
	nDocs := float64(len(docs))

	type scored struct {
		text  string
		score float64
	}
	var results []scored
	for _, d := range docs {
		score := 0.0
		for _, qt := range qTerms {
			tf := float64(d.terms[qt])
			if tf == 0 {
				continue
			}
			docFreq := float64(df[qt])
			idf := math.Log(1.0 + (nDocs-docFreq+0.5)/(docFreq+0.5))
			denom := tf + k1*(1.0-b+b*(float64(d.len)/avgDL))
			score += idf * (tf * (k1 + 1.0)) / denom
		}
		if score > 0 {
			results = append(results, scored{text: d.text, score: score})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})
	if len(results) > limit {
		results = results[:limit]
	}
	out := make([]string, len(results))
	for i, r := range results {
		out[i] = r.text
	}
	return out
}

func splitBlocks(content string) []string {
	raw := strings.Split(content, "\n\n")
	var blocks []string
	for _, b := range raw {
		if t := strings.TrimSpace(b); t != "" {
			blocks = append(blocks, t)
		}
	}
	return blocks
}

func tokenizeWords(s string) []string {
	var tokens []string
	var cur strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			cur.WriteRune(r)
		} else if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}
