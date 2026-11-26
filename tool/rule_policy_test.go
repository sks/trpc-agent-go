//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package tool

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRulePermissionPolicy_ThreeLayerAndSubAgentInheritance(t *testing.T) {
	operatorRules := RuleLayerSet{
		Layer: RuleLayerOperator,
		Rules: []ToolRule{
			{
				ID:     "only-github-mcp",
				Effect: RuleEffectDeny,
				Match:  ToolRuleMatch{Name: "mcp__*"},
				Except: &ToolRuleMatch{Family: "github"},
				Reason: "Only GitHub MCP server is approved.",
			},
			{
				ID:     "hide-legacy-tool",
				Effect: RuleEffectHide,
				Match:  ToolRuleMatch{Name: "internal_debug_*"},
			},
			{
				ID:     "no-shell-on-telegram",
				Effect: RuleEffectDeny,
				Match:  ToolRuleMatch{Name: "run_shell"},
				When:   &ToolRuleWhen{Channel: "telegram"},
				Reason: "Shell is disabled on Telegram.",
			},
		},
	}

	// Orchestrator archetype denies direct run_shell so it delegates to sub-agents.
	orchestratorRules := RuleLayerSet{
		Layer: RuleLayerArchetype,
		Rules: []ToolRule{
			{
				ID:     "planner-no-direct-shell",
				Effect: RuleEffectDeny,
				Match:  ToolRuleMatch{Name: "run_shell"},
				Reason: "Orchestrator must delegate shell execution to a worker.",
			},
		},
	}

	policy := NewRulePermissionPolicy(
		AutonomySupervised,
		NewDefaultSeverityClassifier("/workspace"),
		operatorRules,
		orchestratorRules,
	)

	ctx := context.Background()

	// 1. Non-GitHub MCP is denied on wire, search, and execution.
	assert.False(t, policy.IsVisibleOnWire(ctx, "mcp__slack__post_message"))
	assert.False(t, policy.IsSearchable(ctx, "mcp__slack__post_message"))
	assert.True(t, policy.IsVisibleOnWire(ctx, "mcp__github__get_issue"))
	assert.True(t, policy.IsSearchable(ctx, "mcp__github__get_issue"))

	// 2. Hidden tool is omitted from wire but remains searchable/callable.
	assert.False(t, policy.IsVisibleOnWire(ctx, "internal_debug_dump"))
	assert.True(t, policy.IsSearchable(ctx, "internal_debug_dump"))

	// 3. Orchestrator cannot call run_shell directly.
	dec, err := policy.CheckToolPermission(ctx, &PermissionRequest{
		ToolName:  "run_shell",
		Arguments: []byte(`{"command": "ls -la"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, PermissionActionDeny, dec.Action)
	assert.Contains(t, dec.Reason, "planner-no-direct-shell")

	// 4. Sub-agent inherits OperatorLayer but NOT Orchestrator's ArchetypeLayer denial!
	subPolicy := policy.ForSubAgent(nil)
	subDec, err := subPolicy.CheckToolPermission(ctx, &PermissionRequest{
		ToolName:  "run_shell",
		Arguments: []byte(`{"command": "go test ./..."}`),
	})
	require.NoError(t, err)
	assert.Equal(t, PermissionActionAllow, subDec.Action)

	// 5. Sub-agent still respects OperatorLayer channel restriction (telegram denies run_shell).
	tgCtx := WithRuleRuntimeContext(ctx, RuleRuntimeContext{Channel: "telegram"})
	tgDec, err := subPolicy.CheckToolPermission(tgCtx, &PermissionRequest{
		ToolName:  "run_shell",
		Arguments: []byte(`{"command": "ls"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, PermissionActionDeny, tgDec.Action)
	assert.Contains(t, tgDec.Reason, "no-shell-on-telegram")

	// 6. External trigger origin escalates Low severity (save_file) to Medium -> Ask in Supervised mode.
	extCtx := WithRuleRuntimeContext(ctx, RuleRuntimeContext{Origin: "external_trigger"})
	extRes, err := subPolicy.Evaluate(extCtx, &PermissionRequest{
		ToolName:  "save_file",
		Arguments: []byte(`{"path": "notes.txt", "content": "hi"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, SeverityMedium, extRes.Assessment.Level)
	assert.Equal(t, PermissionActionAsk, extRes.Decision.Action)

	// 7. Protected path floor always denies even if an auto_approve rule matches.
	autoPolicy := NewRulePermissionPolicy(
		AutonomyFull,
		NewDefaultSeverityClassifier("/workspace"),
		RuleLayerSet{
			Layer: RuleLayerOperator,
			Rules: []ToolRule{
				{
					ID:     "auto-approve-all-shell",
					Effect: RuleEffectAutoApprove,
					Match:  ToolRuleMatch{Name: "run_shell"},
				},
			},
		},
	)
	protDec, err := autoPolicy.CheckToolPermission(ctx, &PermissionRequest{
		ToolName:  "run_shell",
		Arguments: []byte(`{"command": "cat ~/.aws/credentials"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, PermissionActionDeny, protDec.Action)
	assert.Contains(t, protDec.Reason, "protected-path-floor")
}
