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
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"trpc.group/trpc-go/trpc-agent-go/tool"
)

func TestCCRStore_PutGetAndEviction(t *testing.T) {
	store := NewCCRStore(2, time.Minute)
	h1 := store.Put("alpha")
	require.True(t, strings.HasPrefix(h1, "⟦ccr:"))
	require.True(t, strings.HasSuffix(h1, "⟧"))

	got, ok := store.Get(h1)
	require.True(t, ok)
	require.Equal(t, "alpha", got)

	rawHash := ParseHandle(h1)
	got2, ok := store.Get(rawHash)
	require.True(t, ok)
	require.Equal(t, "alpha", got2)

	store.Put("beta")
	store.Put("gamma")
	require.Equal(t, 2, store.Len())
}

func TestShapers_ContentTypes(t *testing.T) {
	// JSON tabular array with outlier
	var items []map[string]any
	for i := 0; i < 20; i++ {
		item := map[string]any{"id": i, "status": "ok"}
		if i == 10 {
			item["error"] = "disk full"
		}
		items = append(items, item)
	}
	rawJSON, err := json.Marshal(items)
	require.NoError(t, err)
	shapedJSON, changed := Shape(string(rawJSON), 350, "")
	require.True(t, changed)
	require.Contains(t, shapedJSON, "disk full")
	require.Contains(t, shapedJSON, "more items")

	// Diff with lockfile
	diff := "diff --git a/go.sum b/go.sum\n--- a/go.sum\n+++ b/go.sum\n@@ -1,2 +1,3 @@\n+foo v1.0.0\n-bar v0.1.0\n" +
		"\ndiff --git a/main.go b/main.go\n--- a/main.go\n+++ b/main.go\n@@ -1,1 +1,2 @@\n+println(1)\n"
	shapedDiff, changed := Shape(diff, 160, "")
	require.True(t, changed)
	require.Contains(t, shapedDiff, "go.sum: +1/-1 lines (lockfile compacted)")
	require.Contains(t, shapedDiff, "main.go")

	// Search grouping
	var searchLines []string
	for i := 1; i <= 6; i++ {
		searchLines = append(searchLines, fmt.Sprintf("pkg/foo.go:%d: match_%d", i, i))
	}
	shapedSearch, changed := Shape(strings.Join(searchLines, "\n"), 120, "")
	require.True(t, changed)
	require.Contains(t, shapedSearch, "[+3 more matches in pkg/foo.go]")

	// Code collapsing
	code := "package main\nfunc big() {\n\tif true {\n\t\ta := 1\n\t\tb := 2\n\t\tc := 3\n\t\td := 4\n\t\te := 5\n\t}\n}\n"
	shapedCode, changed := Shape(code, 75, "")
	require.True(t, changed)
	require.Contains(t, shapedCode, "... 5 lines ...")
}

func TestTools_RetrieveAndQuery(t *testing.T) {
	store := NewCCRStore(10, time.Minute)
	ctx := context.Background()
	retrieveTool := NewRetrieveTool(store)
	queryTool := NewQueryTool(store)

	// Retrieve lines & bytes
	hText := store.Put("line1\nline2\nline3\nline4")
	resBytes, err := retrieveTool.Call(ctx, mustJSON(t, RetrieveArgs{Handle: hText, Mode: "lines", Offset: 1, Limit: 2}))
	require.NoError(t, err)
	ret := resBytes.(RetrieveResult)
	require.Equal(t, "line2\nline3", ret.Content)
	require.True(t, ret.Truncated)

	// Regex query
	qRes, err := queryTool.Call(ctx, mustJSON(t, QueryArgs{Handle: hText, Mode: "regex", Query: `line[24]`}))
	require.NoError(t, err)
	qr := qRes.(QueryResult)
	require.Equal(t, []string{"2: line2", "4: line4"}, qr.Matches)

	// JSON gjson query
	hJSON := store.Put(`{"user":{"name":"alice","roles":["admin","dev"]}}`)
	qRes, err = queryTool.Call(ctx, mustJSON(t, QueryArgs{Handle: hJSON, Mode: "json", Query: "user.name"}))
	require.NoError(t, err)
	require.Equal(t, []string{"alice"}, qRes.(QueryResult).Matches)

	// HTML query
	hHTML := store.Put(`<html><body><h1>Title</h1><a href="https://example.com">Docs</a></body></html>`)
	qRes, err = queryTool.Call(ctx, mustJSON(t, QueryArgs{Handle: hHTML, Mode: "html"}))
	require.NoError(t, err)
	require.Len(t, qRes.(QueryResult).Matches, 2)

	// BM25 query
	hBM25 := store.Put("alpha beta gamma\n\ndelta epsilon\n\nalpha alpha target")
	qRes, err = queryTool.Call(ctx, mustJSON(t, QueryArgs{Handle: hBM25, Mode: "bm25", Query: "alpha target", Limit: 1}))
	require.NoError(t, err)
	require.Equal(t, []string{"alpha alpha target"}, qRes.(QueryResult).Matches)
}

func TestPlugin_BeforeAndAfterTool(t *testing.T) {
	p := New(WithThreshold(50), WithMaxChars(40))
	ctx := context.Background()

	beforeRes, err := p.beforeTool(ctx, &tool.BeforeToolArgs{
		ToolCallID: "call-1",
		ToolName:   "read_file",
		Arguments:  []byte(`{"path":"foo.log","result_focus":"ERROR"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, beforeRes)
	require.NotContains(t, string(beforeRes.ModifiedArguments), "result_focus")

	bigLog := "INFO ok 1\nINFO ok 2\nERROR something broke\nINFO ok 3\nINFO ok 4\nINFO ok 5\n"
	afterRes, err := p.afterTool(ctx, &tool.AfterToolArgs{
		ToolCallID: "call-1",
		ToolName:   "read_file",
		Result:     bigLog,
	})
	require.NoError(t, err)
	require.NotNil(t, afterRes)
	compacted, ok := afterRes.CustomResult.(string)
	require.True(t, ok)
	require.Contains(t, compacted, "ERROR something broke")
	require.Contains(t, compacted, "⟦ccr:")
	require.Equal(t, 1, p.Store().Len())
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
