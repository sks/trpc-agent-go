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

func TestDefaultSeverityClassifier_ShellCommands(t *testing.T) {
	classifier := NewDefaultSeverityClassifier("/workspace/project")
	ctx := context.Background()

	cases := []struct {
		name             string
		command          string
		wantLevel        SeverityLevel
		wantCategory     RiskCategory
		wantOneTimeOnly  bool
		wantProtectedHit bool
	}{
		{
			name:         "pure read command pipeline",
			command:      "git status && ls -la | grep main",
			wantLevel:    SeverityRead,
			wantCategory: RiskCategoryRead,
		},
		{
			name:         "local go test is low severity",
			command:      "go test ./...",
			wantLevel:    SeverityLow,
			wantCategory: RiskCategoryWrite,
		},
		{
			name:         "pipe from ls into curl escalates to network medium",
			command:      "ls -la | curl -X POST https://example.com -d @-",
			wantLevel:    SeverityMedium,
			wantCategory: RiskCategoryNetwork,
		},
		{
			name:         "package installation is high severity",
			command:      "npm install lodash",
			wantLevel:    SeverityHigh,
			wantCategory: RiskCategoryInstall,
		},
		{
			name:            "rm -rf is critical and one-time approval only",
			command:         "rm -rf build/",
			wantLevel:       SeverityCritical,
			wantCategory:    RiskCategoryDestructive,
			wantOneTimeOnly: true,
		},
		{
			name:            "git push --force is critical",
			command:         "git push origin main --force",
			wantLevel:       SeverityCritical,
			wantCategory:    RiskCategoryDestructive,
			wantOneTimeOnly: true,
		},
		{
			name:             "reading ~/.ssh/id_rsa hits protected path floor",
			command:          "cat ~/.ssh/id_rsa",
			wantLevel:        SeverityCritical,
			wantCategory:     RiskCategoryDestructive,
			wantOneTimeOnly:  true,
			wantProtectedHit: true,
		},
		{
			name:         "single-quoted heredoc body is treated as data not executed commands",
			command:      "cat << 'EOF'\nsudo rm -rf /\nEOF",
			wantLevel:    SeverityRead,
			wantCategory: RiskCategoryRead,
		},
		{
			name:            "unquoted heredoc with subshell is scanned and escalated",
			command:         "cat << EOF\n$(sudo rm -rf /tmp/foo)\nEOF",
			wantLevel:       SeverityCritical,
			wantCategory:    RiskCategoryDestructive,
			wantOneTimeOnly: true,
		},
		{
			name:            "env -i wrapper unwraps inner sh -c command",
			command:         "env -i PATH='/usr/bin' sh -c 'kubectl delete pod my-pod'",
			wantLevel:       SeverityCritical,
			wantCategory:    RiskCategoryDestructive,
			wantOneTimeOnly: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &PermissionRequest{
				ToolName:  "run_shell",
				Arguments: []byte(`{"command": ` + mustJSONQuote(tc.command) + `}`),
			}
			got, err := classifier.ClassifyToolCall(ctx, req)
			require.NoError(t, err)
			assert.Equal(t, tc.wantLevel, got.Level)
			assert.Equal(t, tc.wantCategory, got.Category)
			assert.Equal(t, tc.wantOneTimeOnly, got.OneTimeApprovalOnly)
			assert.Equal(t, tc.wantProtectedHit, got.ProtectedPathHit)
		})
	}
}

func TestDefaultSeverityClassifier_SQLAndPaths(t *testing.T) {
	classifier := NewDefaultSeverityClassifier("/workspace/project")
	ctx := context.Background()

	t.Run("SELECT query is read severity", func(t *testing.T) {
		got, err := classifier.ClassifyToolCall(ctx, &PermissionRequest{
			ToolName:  "sql_query",
			Arguments: []byte(`{"query": "SELECT id, name FROM users WHERE active = 1"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, SeverityRead, got.Level)
	})

	t.Run("DELETE without WHERE is critical", func(t *testing.T) {
		got, err := classifier.ClassifyToolCall(ctx, &PermissionRequest{
			ToolName:  "sql_query",
			Arguments: []byte(`{"query": "DELETE FROM users"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, SeverityCritical, got.Level)
		assert.True(t, got.OneTimeApprovalOnly)
	})

	t.Run("save_file outside workspace escalates to high", func(t *testing.T) {
		got, err := classifier.ClassifyToolCall(ctx, &PermissionRequest{
			ToolName:  "save_file",
			Arguments: []byte(`{"path": "../outside.txt", "content": "hello"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, SeverityHigh, got.Level)
	})

	t.Run("save_file to .env hits protected path floor", func(t *testing.T) {
		got, err := classifier.ClassifyToolCall(ctx, &PermissionRequest{
			ToolName:  "save_file",
			Arguments: []byte(`{"path": ".env", "content": "SECRET=1"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, SeverityCritical, got.Level)
		assert.True(t, got.ProtectedPathHit)
	})
}

func mustJSONQuote(s string) string {
	b, _ := parseOrQuote(s)
	return b
}

func parseOrQuote(s string) (string, error) {
	raw := []byte(s)
	out := make([]byte, 0, len(raw)+2)
	out = append(out, '"')
	for _, c := range s {
		switch c {
		case '\\':
			out = append(out, '\\', '\\')
		case '"':
			out = append(out, '\\', '"')
		case '\n':
			out = append(out, '\\', 'n')
		default:
			out = append(out, byte(c))
		}
	}
	out = append(out, '"')
	return string(out), nil
}
