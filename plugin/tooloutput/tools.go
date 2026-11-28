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
func NewTools(store OutputStore) []tool.Tool {
	return []tool.Tool{
		NewRetrieveTool(store),
		NewQueryTool(store),
	}
}

// NewRetrieveTool creates a thin function.NewFunctionTool adapter over QueryEngine.Retrieve.
func NewRetrieveTool(store OutputStore) tool.CallableTool {
	engine := NewQueryEngine(store)
	return function.NewFunctionTool(
		func(_ context.Context, args RetrieveArgs) (RetrieveResult, error) {
			return engine.Retrieve(args)
		},
		function.WithName("tool_result_retrieve"),
		function.WithDescription("Retrieve a byte or line range from a compacted tool output stored in CCR using its ⟦ccr:...⟧ handle."),
	)
}

// NewQueryTool creates a thin function.NewFunctionTool adapter over QueryEngine.Query.
func NewQueryTool(store OutputStore) tool.CallableTool {
	engine := NewQueryEngine(store)
	return function.NewFunctionTool(
		func(_ context.Context, args QueryArgs) (QueryResult, error) {
			return engine.Query(args)
		},
		function.WithName("tool_result_query"),
		function.WithDescription("Query a compacted tool output stored in CCR without LLM calls using regex, json (gjson path), html (links/headings), or bm25 block ranking."),
	)
}
