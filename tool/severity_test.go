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

func TestSeverityAssessment_RaiseAndMerge(t *testing.T) {
	var a SeverityAssessment
	a.Raise(SeverityLow, RiskCategoryWrite, "local edit")
	a.Raise(SeverityLow, RiskCategoryWrite, "local edit") // deduplicated
	assert.Equal(t, SeverityLow, a.Level)
	assert.Equal(t, RiskCategoryWrite, a.Category)
	assert.Equal(t, []string{"local edit"}, a.Reasons)

	other := SeverityAssessment{
		Level:            SeverityCritical,
		Category:         RiskCategoryDestructive,
		Reasons:          []string{"protected path hit"},
		ProtectedPathHit: true,
	}.Finalize()
	a.Merge(other)
	assert.Equal(t, SeverityCritical, a.Level)
	assert.Equal(t, RiskCategoryDestructive, a.Category)
	assert.True(t, a.OneTimeApprovalOnly)
	assert.True(t, a.ProtectedPathHit)
	assert.Len(t, a.Reasons, 2)
}

func TestDefaultSeverityClassifier_HTTPAndPluggableAnalyzers(t *testing.T) {
	ctx := context.Background()

	// Custom Python snippet analyzer plugged in via ArgRiskAnalyzerFunc.
	pythonAnalyzer := ArgRiskAnalyzerFunc(func(input SeverityInput, assessment *SeverityAssessment) {
		if input.ToolName != "python_eval" {
			return
		}
		code, _ := input.Args["code"].(string)
		if code == "import shutil; shutil.rmtree('/')" {
			assessment.Raise(SeverityCritical, RiskCategoryDestructive, "python rmtree('/') detected")
		}
	})

	classifier := NewSeverityClassifier(
		WithWorkspaceDir("/workspace/project"),
		WithExtraProtectedGlobs("**/vault.token"),
		WithArgAnalyzers(pythonAnalyzer),
	)

	t.Run("HTTP GET is read severity", func(t *testing.T) {
		got, err := classifier.ClassifyToolCall(ctx, &PermissionRequest{
			ToolName:  "http_request",
			Arguments: []byte(`{"method": "GET", "url": "https://api.example.com/v1/items"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, SeverityRead, got.Level)
		assert.Equal(t, RiskCategoryRead, got.Category)
	})

	t.Run("HTTP DELETE is high destructive severity", func(t *testing.T) {
		got, err := classifier.ClassifyToolCall(ctx, &PermissionRequest{
			ToolName:  "http_request",
			Arguments: []byte(`{"method": "DELETE", "url": "https://api.example.com/v1/items/42"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, SeverityHigh, got.Level)
		assert.Equal(t, RiskCategoryDestructive, got.Category)
	})

	t.Run("HTTP cloud metadata URL escalates to critical protected hit", func(t *testing.T) {
		got, err := classifier.ClassifyToolCall(ctx, &PermissionRequest{
			ToolName:  "http_request",
			Arguments: []byte(`{"method": "GET", "url": "http://169.254.169.254/latest/meta-data/iam/"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, SeverityCritical, got.Level)
		assert.True(t, got.ProtectedPathHit)
		assert.True(t, got.OneTimeApprovalOnly)
	})

	t.Run("custom ArgRiskAnalyzer escalates domain-specific tool call", func(t *testing.T) {
		got, err := classifier.ClassifyToolCall(ctx, &PermissionRequest{
			ToolName:  "python_eval",
			Arguments: []byte(`{"code": "import shutil; shutil.rmtree('/')"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, SeverityCritical, got.Level)
		assert.Equal(t, RiskCategoryDestructive, got.Category)
		assert.True(t, got.OneTimeApprovalOnly)
	})

	t.Run("custom CommandRiskAnalyzer overrides shell analyzer", func(t *testing.T) {
		customShell := NewSeverityClassifier(
			WithShellAnalyzer(CommandRiskAnalyzerFunc(func(command string) SeverityAssessment {
				return SeverityAssessment{
					Level:    SeverityHigh,
					Category: RiskCategoryInstall,
					Reasons:  []string{"custom shell policy: " + command},
				}
			})),
		)
		got, err := customShell.ClassifyToolCall(ctx, &PermissionRequest{
			ToolName:  "run_shell",
			Arguments: []byte(`{"command": "echo hi"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, SeverityHigh, got.Level)
		assert.Equal(t, RiskCategoryInstall, got.Category)
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
