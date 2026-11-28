//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package tooloutput

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/tidwall/gjson"
	"golang.org/x/net/html"
)

const (
	defaultLineRetrieveLimit = 100
	defaultByteRetrieveLimit = 4000
	defaultQueryMatchLimit   = 20
)

// QueryEngine executes deterministic slice retrieval and zero-LLM structured
// queries (regex, gjson, HTML, BM25) against an OutputStore.
type QueryEngine struct {
	store OutputStore
}

// NewQueryEngine creates a QueryEngine backed by store.
func NewQueryEngine(store OutputStore) *QueryEngine {
	return &QueryEngine{store: store}
}

func (e *QueryEngine) resolve(handle string) (string, error) {
	if e == nil || e.store == nil {
		return "", fmt.Errorf("ccr handle not found: %s", handle)
	}
	content, ok := e.store.Get(handle)
	if !ok {
		return "", fmt.Errorf("ccr handle not found: %s", handle)
	}
	return content, nil
}

// Retrieve dispatches a line or byte range request.
func (e *QueryEngine) Retrieve(args RetrieveArgs) (RetrieveResult, error) {
	mode := strings.ToLower(strings.TrimSpace(args.Mode))
	if mode == "bytes" {
		return e.RetrieveBytes(args.Handle, args.Offset, args.Limit)
	}
	return e.RetrieveLines(args.Handle, args.Offset, args.Limit)
}

// RetrieveLines returns a 0-based line slice from the stored output identified by handle.
func (e *QueryEngine) RetrieveLines(handle string, offset, limit int) (RetrieveResult, error) {
	content, err := e.resolve(handle)
	if err != nil {
		return RetrieveResult{}, err
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = defaultLineRetrieveLimit
	}
	lines := strings.Split(content, "\n")
	total := len(lines)
	if offset >= total {
		return RetrieveResult{Handle: handle, Mode: "lines", Offset: offset, Total: total}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	slice := strings.Join(lines[offset:end], "\n")
	return RetrieveResult{
		Handle:    handle,
		Mode:      "lines",
		Offset:    offset,
		Total:     total,
		Returned:  end - offset,
		Content:   slice,
		Truncated: end < total,
	}, nil
}

// RetrieveBytes returns a 0-based byte slice from the stored output identified by handle.
func (e *QueryEngine) RetrieveBytes(handle string, offset, limit int) (RetrieveResult, error) {
	content, err := e.resolve(handle)
	if err != nil {
		return RetrieveResult{}, err
	}
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = defaultByteRetrieveLimit
	}
	total := len(content)
	if offset >= total {
		return RetrieveResult{Handle: handle, Mode: "bytes", Offset: offset, Total: total}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	slice := content[offset:end]
	return RetrieveResult{
		Handle:    handle,
		Mode:      "bytes",
		Offset:    offset,
		Total:     total,
		Returned:  len(slice),
		Content:   slice,
		Truncated: end < total,
	}, nil
}

// Query dispatches a structured query across regex, json, html, or bm25 modes.
func (e *QueryEngine) Query(args QueryArgs) (QueryResult, error) {
	mode := strings.ToLower(strings.TrimSpace(args.Mode))
	switch mode {
	case "regex", "grep":
		res, err := e.QueryRegex(args.Handle, args.Query, args.Limit)
		if err != nil {
			return QueryResult{}, err
		}
		res.Mode = mode
		return res, nil
	case "json", "gjson":
		res, err := e.QueryGJSON(args.Handle, args.Query, args.Limit)
		if err != nil {
			return QueryResult{}, err
		}
		res.Mode = mode
		return res, nil
	case "html":
		return e.QueryHTML(args.Handle, args.Query, args.Limit)
	case "bm25":
		return e.QueryBM25(args.Handle, args.Query, args.Limit)
	default:
		return QueryResult{}, fmt.Errorf("unsupported query mode %q (use regex, json, html, or bm25)", args.Mode)
	}
}

// QueryRegex searches lines of a stored output matching pattern.
func (e *QueryEngine) QueryRegex(handle, pattern string, limit int) (QueryResult, error) {
	content, err := e.resolve(handle)
	if err != nil {
		return QueryResult{}, err
	}
	if limit <= 0 {
		limit = defaultQueryMatchLimit
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return QueryResult{}, fmt.Errorf("invalid regex: %w", err)
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
	return QueryResult{
		Handle:  handle,
		Mode:    "regex",
		Matches: matches,
		Count:   len(matches),
	}, nil
}

// QueryGJSON extracts JSON values at path using tidwall/gjson.
func (e *QueryEngine) QueryGJSON(handle, path string, limit int) (QueryResult, error) {
	content, err := e.resolve(handle)
	if err != nil {
		return QueryResult{}, err
	}
	if limit <= 0 {
		limit = defaultQueryMatchLimit
	}
	res := gjson.Get(content, path)
	var matches []string
	if res.Exists() {
		if res.IsArray() {
			res.ForEach(func(_, v gjson.Result) bool {
				matches = append(matches, v.String())
				return len(matches) < limit
			})
		} else {
			matches = []string{res.String()}
		}
	}
	return QueryResult{
		Handle:  handle,
		Mode:    "json",
		Matches: matches,
		Count:   len(matches),
	}, nil
}

// QueryHTML extracts links and headings from an HTML document, filtered by substring filter.
func (e *QueryEngine) QueryHTML(handle, filter string, limit int) (QueryResult, error) {
	content, err := e.resolve(handle)
	if err != nil {
		return QueryResult{}, err
	}
	if limit <= 0 {
		limit = defaultQueryMatchLimit
	}
	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return QueryResult{}, fmt.Errorf("html parse error: %w", err)
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
	return QueryResult{
		Handle:  handle,
		Mode:    "html",
		Matches: matches,
		Count:   len(matches),
	}, nil
}

// QueryBM25 ranks paragraph blocks in the stored output against query using Okapi BM25.
func (e *QueryEngine) QueryBM25(handle, query string, limit int) (QueryResult, error) {
	content, err := e.resolve(handle)
	if err != nil {
		return QueryResult{}, err
	}
	if limit <= 0 {
		limit = defaultQueryMatchLimit
	}
	matches := rankBlocksBM25(content, query, limit)
	return QueryResult{
		Handle:  handle,
		Mode:    "bm25",
		Matches: matches,
		Count:   len(matches),
	}, nil
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

func rankBlocksBM25(content, query string, limit int) []string {
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
