//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
// trpc-agent-go is licensed under the Apache License Version 2.0.
//
//

package toolsearch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"trpc.group/trpc-go/trpc-agent-go/knowledge/vectorstore/inmemory"
	"trpc.group/trpc-go/trpc-agent-go/tool"
	"trpc.group/trpc-go/trpc-agent-go/tool/function"
)

type cacheCountingEmbedder struct {
	fakeEmbedder
	calls int
}

func (e *cacheCountingEmbedder) GetEmbeddingWithUsage(ctx context.Context, text string) ([]float64, map[string]any, error) {
	e.calls++
	return e.fakeEmbedder.GetEmbeddingWithUsage(ctx, text)
}

func TestComputeToolContentHash_ExactFormat(t *testing.T) {
	schema := &tool.Schema{
		Type: "object",
		Properties: map[string]*tool.Schema{
			"city": {Type: "string", Description: "Target city"},
		},
	}
	tl := function.NewFunctionTool(
		func(ctx context.Context, in struct{}) (string, error) { return "", nil },
		function.WithName("get_weather"),
		function.WithDescription("Get weather forecast"),
		function.WithInputSchema(schema),
	)

	schemaJSON, err := json.Marshal(tl.Declaration().InputSchema)
	require.NoError(t, err)
	expectedRaw := "get_weather\x00Get weather forecast\x00" + string(schemaJSON)
	expectedSum := sha256.Sum256([]byte(expectedRaw))
	expectedHex := hex.EncodeToString(expectedSum[:])

	actual := ComputeToolContentHash(tl)
	assert.Equal(t, expectedHex, actual)
	assert.Empty(t, ComputeToolContentHash(nil))
	assert.Empty(t, ComputeDeclarationContentHash(nil))
}

func TestEmbeddingCache_SkipsReEmbeddingAcrossRestarts(t *testing.T) {
	weather := newTestTool("get_weather", "weather forecast")
	timeTool := newTestTool("get_time", "current time")

	emb := &cacheCountingEmbedder{
		fakeEmbedder: fakeEmbedder{vectors: map[string][]float64{
			"weather":            {1, 0, 0},
			toolToText(weather):  {1, 0, 0},
			toolToText(timeTool): {0, 1, 0},
		}},
	}
	sharedCache := NewEmbeddingCache()

	// First startup / index pass embeds both tools + 1 query = 3 embedder calls.
	k1, err := NewSemanticToolIndex(emb, WithVectorStore(inmemory.New()), WithEmbeddingCache(sharedCache))
	require.NoError(t, err)
	p1 := New(nil,
		WithSemanticToolIndex(k1),
		WithToolboxes([]Toolbox{{
			Name:  "utility",
			Tools: []tool.Tool{weather, timeTool},
		}}),
	)
	ctx, _ := ctxWithInvocation()
	res1 := callSearch(t, ctx, p1, toolSearchInput{Queries: []string{"weather"}, MaxResults: 1})
	require.Len(t, res1.Tools, 1)
	assert.Equal(t, "get_weather", res1.Tools[0].Name)
	assert.Equal(t, 3, emb.calls, "first run embeds 2 tools + 1 query")

	// Second startup with a fresh SemanticToolIndex sharing the EmbeddingCache
	// skips re-embedding the 2 unchanged tools and only embeds the query (1 call).
	k2, err := NewSemanticToolIndex(emb, WithVectorStore(inmemory.New()), WithEmbeddingCache(sharedCache))
	require.NoError(t, err)
	p2 := New(nil,
		WithSemanticToolIndex(k2),
		WithToolboxes([]Toolbox{{
			Name:  "utility",
			Tools: []tool.Tool{weather, timeTool},
		}}),
	)
	res2 := callSearch(t, ctx, p2, toolSearchInput{Queries: []string{"weather"}, MaxResults: 1})
	require.Len(t, res2.Tools, 1)
	assert.Equal(t, "get_weather", res2.Tools[0].Name)
	assert.Equal(t, 4, emb.calls, "second run must reuse cached tool vectors and only embed the query")

	hits, misses, entries := sharedCache.Stats()
	assert.Equal(t, int64(2), hits)
	assert.Equal(t, int64(2), misses)
	assert.Equal(t, 2, entries)
	assert.True(t, sharedCache.IsUnchanged("get_weather", ComputeToolContentHash(weather)))
}

func TestExtractToolFamily(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		want     string
	}{
		{name: "mcp tool", toolName: "mcp__github__create_pull_request", want: "mcp__github"},
		{name: "mcp tool uppercase", toolName: "MCP__Slack__Post_Message", want: "mcp__slack"},
		{name: "double underscore non-mcp", toolName: "aws__s3__list_buckets", want: "aws"},
		{name: "prefix underscore", toolName: "github_list_issues", want: "github"},
		{name: "hyphenated prefix underscore", toolName: "evals-grafana_list_datasources", want: "evals-grafana"},
		{name: "dot separator", toolName: "k8s.pods.list", want: "k8s"},
		{name: "single token", toolName: "calculator", want: "calculator"},
		{name: "empty", toolName: "   ", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ExtractToolFamily(tc.toolName))
		})
	}
}

func TestNarrowByToolFamily(t *testing.T) {
	candidates := []ScoredCandidate{
		{Name: "mcp__github__create_pr", Score: 0.88},
		{Name: "mcp__github__list_prs", Score: 0.84},
		{Name: "mcp__slack__post_message", Score: 0.79},
		{Name: "mcp__jira__create_issue", Score: 0.72},
		{Name: "datadog_query_metrics", Score: 0.65},
	}

	narrowed := NarrowByToolFamily(candidates, []string{"github pull requests"}, 1)
	require.Len(t, narrowed, 2)
	assert.Equal(t, "mcp__github__create_pr", narrowed[0].Name)
	assert.Equal(t, "mcp__github__list_prs", narrowed[1].Name)

	narrowed2 := NarrowByToolFamily(candidates, []string{"notify slack about pr"}, 2)
	require.Len(t, narrowed2, 3)
}

func TestAbstention_ConversationalNoToolIntentReturnsEmpty(t *testing.T) {
	weather := newTestTool("github_list_issues", "List issues in a GitHub repository")
	slack := newTestTool("slack_post_message", "Post a message to a Slack channel")

	// Conversational query has weak cosine similarity to both tools (0.20 and 0.18).
	emb := &fakeEmbedder{vectors: map[string][]float64{
		toolToText(weather):         {1, 0, 0},
		toolToText(slack):           {0, 1, 0},
		"hello how are you today":   {0.20, 0.18, 0.96},
		"list open github issues":   {0.95, 0.05, 0.0},
		"ambiguous low gap request": {0.60, 0.59, 0.54},
	}}
	k, err := NewSemanticToolIndex(emb, WithVectorStore(inmemory.New()))
	require.NoError(t, err)

	p := New(nil,
		WithSemanticToolIndex(k),
		WithAbstentionConfig(AbstentionConfig{
			MinScore:              0.45,
			MinScoreGap:           0.05,
			RequireLexicalOverlap: true,
			TopFamilies:           2,
		}),
		WithToolboxes([]Toolbox{{
			Name:  "integrations",
			Tools: []tool.Tool{weather, slack},
		}}),
	)
	ctx, _ := ctxWithInvocation()

	// 1. Conversational query falls below MinScore (0.20 < 0.45) -> abstains (0 tools).
	resChat := callSearch(t, ctx, p, toolSearchInput{Queries: []string{"hello how are you today"}})
	assert.Empty(t, resChat.Tools, "conversational query must abstain instead of returning top-K false positives")
	assert.Empty(t, resChat.AdditionalCandidates)

	// 2. Ambiguous low-gap query (0.60 vs 0.59, gap 0.01 < 0.05) -> abstains.
	resAmbiguous := callSearch(t, ctx, p, toolSearchInput{Queries: []string{"ambiguous low gap request"}})
	assert.Empty(t, resAmbiguous.Tools, "low score-gap query without high confidence must abstain")

	// 3. Clear tool query (0.95 >= 0.45, gap 0.90 >= 0.05, lexical overlap "github"/"issues") -> returns tool.
	resValid := callSearch(t, ctx, p, toolSearchInput{Queries: []string{"list open github issues"}, MaxResults: 1})
	require.Len(t, resValid.Tools, 1)
	assert.Equal(t, "github_list_issues", resValid.Tools[0].Name)
}

func TestAbstention_KeywordPathAndTwoStageFamilyNarrowing(t *testing.T) {
	gh1 := newTestTool("mcp__github__list_commits", "List commits in a GitHub repository")
	gh2 := newTestTool("mcp__github__get_commit", "Get details of a specific commit in a GitHub repository")
	sl1 := newTestTool("mcp__slack__list_channels", "List public channels in Slack workspace")
	jr1 := newTestTool("mcp__jira__list_projects", "List Jira projects")

	p := New(nil,
		WithAbstentionConfig(AbstentionConfig{
			MinScore:    10,
			TopFamilies: 1,
		}),
		WithToolboxes([]Toolbox{{
			Name:  "all",
			Tools: []tool.Tool{gh1, gh2, sl1, jr1},
		}}),
	)
	ctx, _ := ctxWithInvocation()

	// Query "github commit" hits mcp__github family strongly; TopFamilies: 1
	// narrows out mcp__slack and mcp__jira even if generic tokens appear.
	res := callSearch(t, ctx, p, toolSearchInput{Namespace: "all", Queries: []string{"github commit list"}})
	require.NotEmpty(t, res.Tools)
	for _, toolSummary := range res.Tools {
		assert.Equal(t, "mcp__github", ExtractToolFamily(toolSummary.Name))
	}
}
