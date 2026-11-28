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
	"encoding/json"
	"fmt"
	"strings"
)

// SeverityLevel ranks the operational blast radius of a tool invocation.
type SeverityLevel int

const (
	// SeverityRead indicates a provably read-only or observational tool call.
	SeverityRead SeverityLevel = iota
	// SeverityLow indicates a reversible, workspace-local write or build/test action.
	SeverityLow
	// SeverityMedium indicates external network access or shared team mutation.
	SeverityMedium
	// SeverityHigh indicates package installation, infrastructure/config change, or external communication.
	SeverityHigh
	// SeverityCritical indicates destructive, irreversible, privilege-escalating, or credential-touching operations.
	SeverityCritical
)

// String returns the canonical lowercase name of the severity level.
func (s SeverityLevel) String() string {
	switch s {
	case SeverityRead:
		return "read"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverityLevel parses a severity string into a SeverityLevel.
// Unrecognized strings fail closed to SeverityMedium.
func ParseSeverityLevel(raw string) (SeverityLevel, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "read", "readonly", "read_only":
		return SeverityRead, nil
	case "low":
		return SeverityLow, nil
	case "medium", "med":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical", "destructive":
		return SeverityCritical, nil
	default:
		return SeverityMedium, fmt.Errorf("unknown severity level %q", raw)
	}
}

// RiskCategory describes the primary operational class of a tool invocation.
type RiskCategory string

const (
	// RiskCategoryRead covers observational actions with no external side effects.
	RiskCategoryRead RiskCategory = "read"
	// RiskCategoryWrite covers local or remote state modifications.
	RiskCategoryWrite RiskCategory = "write"
	// RiskCategoryNetwork covers outbound network requests and remote shell/transfer tools.
	RiskCategoryNetwork RiskCategory = "network"
	// RiskCategoryInstall covers OS or language package installation.
	RiskCategoryInstall RiskCategory = "install"
	// RiskCategoryDestructive covers irreversible deletion, force-overwrites, privilege escalation, or secret access.
	RiskCategoryDestructive RiskCategory = "destructive"
)

// SeverityInput is the normalized domain value object passed to risk analyzers
// during tool-call classification.
type SeverityInput struct {
	// ToolName is the model-visible tool name.
	ToolName string
	// Metadata holds static capability flags published by the tool.
	Metadata ToolMetadata
	// Declaration is the optional tool schema declaration.
	Declaration *Declaration
	// RawArgs holds the raw JSON-encoded tool arguments.
	RawArgs []byte
	// Args holds the decoded JSON object arguments when RawArgs is a JSON object.
	Args map[string]any
}

// NewSeverityInput normalizes a PermissionRequest into a SeverityInput value object.
func NewSeverityInput(req *PermissionRequest) SeverityInput {
	if req == nil {
		return SeverityInput{}
	}
	meta := req.Metadata
	if req.Tool != nil && !meta.ReadOnly && !meta.Destructive && !meta.SearchOrRead && !meta.OpenWorld {
		meta = MetadataOf(req.Tool)
	}
	decl := req.Declaration
	if decl == nil && req.Tool != nil {
		decl = req.Tool.Declaration()
	}
	return SeverityInput{
		ToolName:    req.ToolName,
		Metadata:    meta,
		Declaration: decl,
		RawArgs:     req.Arguments,
		Args:        parseJSONArgumentsMap(req.Arguments),
	}
}

// SeverityAssessment holds the computed severity and supporting evidence for a tool call.
type SeverityAssessment struct {
	// Level is the computed severity tier (Read .. Critical).
	Level SeverityLevel `json:"level"`
	// Category is the primary operational risk category.
	Category RiskCategory `json:"category"`
	// Reasons lists human-readable explanations for why this severity was assigned.
	Reasons []string `json:"reasons,omitempty"`
	// OneTimeApprovalOnly is true when the call must not be auto-approved via session cache
	// or added to an "Always allow" list (for example, SeverityCritical or browser/financial actions).
	OneTimeApprovalOnly bool `json:"one_time_approval_only,omitempty"`
	// ProtectedPathHit is true when arguments touch credential stores or system roots (~/.ssh, ~/.aws, .env, etc.).
	ProtectedPathHit bool `json:"protected_path_hit,omitempty"`
}

// Raise monotonic-escalates the assessment's level and category when level exceeds
// the current tier, deduplicating non-empty reasons and enforcing OneTimeApprovalOnly
// on SeverityCritical.
func (a *SeverityAssessment) Raise(level SeverityLevel, category RiskCategory, reason string) {
	if a == nil {
		return
	}
	if level > a.Level {
		a.Level = level
		a.Category = category
	}
	if level == SeverityCritical {
		a.OneTimeApprovalOnly = true
	}
	if reason != "" {
		for _, existing := range a.Reasons {
			if existing == reason {
				return
			}
		}
		a.Reasons = append(a.Reasons, reason)
	}
}

// Merge folds another SeverityAssessment into a, preserving the maximum severity tier,
// boolean safety flags, and deduplicated reasons.
func (a *SeverityAssessment) Merge(other SeverityAssessment) {
	if a == nil {
		return
	}
	if other.Level > a.Level {
		a.Level = other.Level
		a.Category = other.Category
	}
	if other.OneTimeApprovalOnly {
		a.OneTimeApprovalOnly = true
	}
	if other.ProtectedPathHit {
		a.ProtectedPathHit = true
	}
	for _, r := range other.Reasons {
		a.Raise(a.Level, a.Category, r)
	}
}

// Finalize normalizes invariants on a completed SeverityAssessment.
func (a SeverityAssessment) Finalize() SeverityAssessment {
	if a.Level == SeverityCritical {
		a.OneTimeApprovalOnly = true
	}
	if a.Category == "" {
		if a.Level == SeverityRead {
			a.Category = RiskCategoryRead
		} else {
			a.Category = RiskCategoryWrite
		}
	}
	return a
}

// SeverityClassifier evaluates the runtime severity of a pending tool call.
type SeverityClassifier interface {
	ClassifyToolCall(ctx context.Context, req *PermissionRequest) (SeverityAssessment, error)
}

// SeverityClassifierFunc adapts a function to SeverityClassifier.
type SeverityClassifierFunc func(ctx context.Context, req *PermissionRequest) (SeverityAssessment, error)

// ClassifyToolCall implements SeverityClassifier.
func (f SeverityClassifierFunc) ClassifyToolCall(ctx context.Context, req *PermissionRequest) (SeverityAssessment, error) {
	if f == nil {
		return SeverityAssessment{Level: SeverityRead, Category: RiskCategoryRead}, nil
	}
	return f(ctx, req)
}

// CommandRiskAnalyzer inspects a command or query string (such as a shell script
// or SQL statement) and returns its assessed operational risk.
type CommandRiskAnalyzer interface {
	AnalyzeCommand(command string) SeverityAssessment
}

// CommandRiskAnalyzerFunc adapts a function to CommandRiskAnalyzer.
type CommandRiskAnalyzerFunc func(command string) SeverityAssessment

// AnalyzeCommand implements CommandRiskAnalyzer.
func (f CommandRiskAnalyzerFunc) AnalyzeCommand(command string) SeverityAssessment {
	if f == nil {
		return SeverityAssessment{Level: SeverityRead, Category: RiskCategoryRead}
	}
	return f(command)
}

// ArgRiskAnalyzer inspects structured tool invocation arguments and raises or
// merges findings onto an in-progress SeverityAssessment.
type ArgRiskAnalyzer interface {
	AnalyzeArgs(input SeverityInput, assessment *SeverityAssessment)
}

// ArgRiskAnalyzerFunc adapts a function to ArgRiskAnalyzer.
type ArgRiskAnalyzerFunc func(input SeverityInput, assessment *SeverityAssessment)

// AnalyzeArgs implements ArgRiskAnalyzer.
func (f ArgRiskAnalyzerFunc) AnalyzeArgs(input SeverityInput, assessment *SeverityAssessment) {
	if f != nil {
		f(input, assessment)
	}
}

// SeverityOption configures a DefaultSeverityClassifier.
type SeverityOption func(*DefaultSeverityClassifier)

// WithWorkspaceDir sets the allowed workspace root outside which write paths escalate severity.
func WithWorkspaceDir(dir string) SeverityOption {
	return func(c *DefaultSeverityClassifier) {
		c.WorkspaceDir = dir
	}
}

// WithExtraProtectedGlobs appends protected-path globs on top of DefaultProtectedPathGlobs.
func WithExtraProtectedGlobs(globs ...string) SeverityOption {
	return func(c *DefaultSeverityClassifier) {
		c.ExtraProtectedGlobs = append(c.ExtraProtectedGlobs, globs...)
	}
}

// WithShellAnalyzer overrides the CommandRiskAnalyzer used for shell commands.
func WithShellAnalyzer(analyzer CommandRiskAnalyzer) SeverityOption {
	return func(c *DefaultSeverityClassifier) {
		if analyzer != nil {
			c.shellAnalyzer = analyzer
		}
	}
}

// WithSQLAnalyzer overrides the CommandRiskAnalyzer used for SQL statements.
func WithSQLAnalyzer(analyzer CommandRiskAnalyzer) SeverityOption {
	return func(c *DefaultSeverityClassifier) {
		if analyzer != nil {
			c.sqlAnalyzer = analyzer
		}
	}
}

// WithHTTPAnalyzer overrides the ArgRiskAnalyzer used for HTTP requests.
func WithHTTPAnalyzer(analyzer ArgRiskAnalyzer) SeverityOption {
	return func(c *DefaultSeverityClassifier) {
		if analyzer != nil {
			c.httpAnalyzer = analyzer
		}
	}
}

// WithArgAnalyzers registers additional custom language or domain ArgRiskAnalyzers
// evaluated after built-in analyzers.
func WithArgAnalyzers(analyzers ...ArgRiskAnalyzer) SeverityOption {
	return func(c *DefaultSeverityClassifier) {
		for _, a := range analyzers {
			if a != nil {
				c.customArgAnalyzers = append(c.customArgAnalyzers, a)
			}
		}
	}
}

var _ SeverityClassifier = (*DefaultSeverityClassifier)(nil)

// DefaultSeverityClassifier orchestrates static ToolMetadata heuristics and
// pluggable shell, SQL, HTTP, path, and custom domain risk analyzers.
type DefaultSeverityClassifier struct {
	// WorkspaceDir is the optional allowed workspace root; writes outside this directory escalate severity.
	WorkspaceDir string
	// ExtraProtectedGlobs adds host-configured protected path globs on top of DefaultProtectedPathGlobs.
	ExtraProtectedGlobs []string

	shellAnalyzer      CommandRiskAnalyzer
	sqlAnalyzer        CommandRiskAnalyzer
	httpAnalyzer       ArgRiskAnalyzer
	customArgAnalyzers []ArgRiskAnalyzer
}

// NewSeverityClassifier constructs a DefaultSeverityClassifier with functional options.
func NewSeverityClassifier(opts ...SeverityOption) *DefaultSeverityClassifier {
	c := &DefaultSeverityClassifier{}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// NewDefaultSeverityClassifier constructs a DefaultSeverityClassifier for workspaceDir
// and optional extraProtectedGlobs.
func NewDefaultSeverityClassifier(workspaceDir string, extraProtectedGlobs ...string) *DefaultSeverityClassifier {
	return NewSeverityClassifier(
		WithWorkspaceDir(workspaceDir),
		WithExtraProtectedGlobs(extraProtectedGlobs...),
	)
}

// ClassifyToolCall evaluates req and returns a SeverityAssessment.
func (c *DefaultSeverityClassifier) ClassifyToolCall(_ context.Context, req *PermissionRequest) (SeverityAssessment, error) {
	if req == nil {
		return SeverityAssessment{
			Level:    SeverityRead,
			Category: RiskCategoryRead,
		}, nil
	}

	input := NewSeverityInput(req)
	assessment := c.baseAssessmentFromToolAndMeta(input.ToolName, input.Metadata)

	if len(input.Args) > 0 {
		c.inspectBuiltInAnalyzers(input, &assessment)
	}
	for _, custom := range c.customArgAnalyzers {
		custom.AnalyzeArgs(input, &assessment)
	}
	return assessment.Finalize(), nil
}

// ClassifyShellCommand delegates shell command classification to the configured
// shell CommandRiskAnalyzer (defaulting to the mvdan.cc/sh/v3/syntax AST analyzer).
func (c *DefaultSeverityClassifier) ClassifyShellCommand(command string) SeverityAssessment {
	return c.effectiveShellAnalyzer().AnalyzeCommand(command)
}

func (c *DefaultSeverityClassifier) effectivePathGuard() *pathGuard {
	if c == nil {
		return newPathGuard("")
	}
	return newPathGuard(c.WorkspaceDir, c.ExtraProtectedGlobs...)
}

func (c *DefaultSeverityClassifier) effectiveShellAnalyzer() CommandRiskAnalyzer {
	if c != nil && c.shellAnalyzer != nil {
		return c.shellAnalyzer
	}
	return newShellASTAnalyzer(c.effectivePathGuard())
}

func (c *DefaultSeverityClassifier) effectiveSQLAnalyzer() CommandRiskAnalyzer {
	if c != nil && c.sqlAnalyzer != nil {
		return c.sqlAnalyzer
	}
	return newSQLRiskAnalyzer()
}

func (c *DefaultSeverityClassifier) effectiveHTTPAnalyzer() ArgRiskAnalyzer {
	if c != nil && c.httpAnalyzer != nil {
		return c.httpAnalyzer
	}
	return newHTTPRiskAnalyzer()
}

func (c *DefaultSeverityClassifier) inspectBuiltInAnalyzers(input SeverityInput, assessment *SeverityAssessment) {
	lowerTool := strings.ToLower(strings.TrimSpace(input.ToolName))

	// 1. Protected-path floor and workspace-containment check across all string leaves.
	c.effectivePathGuard().AnalyzeArgs(input, assessment)

	// 2. Shell command AST analysis.
	if isShellToolName(lowerTool) {
		foundShell := false
		shellAnalyzer := c.effectiveShellAnalyzer()
		for _, key := range []string{"command", "cmd", "script", "code"} {
			if raw, ok := input.Args[key].(string); ok && strings.TrimSpace(raw) != "" {
				foundShell = true
				assessment.Merge(shellAnalyzer.AnalyzeCommand(raw))
			}
		}
		if !foundShell {
			assessment.Raise(SeverityMedium, RiskCategoryWrite, "shell tool invoked without inspectable command string")
		}
	}

	// 3. SQL query analysis.
	sqlTool := isSQLToolName(lowerTool)
	foundSQL := false
	sqlAnalyzer := c.effectiveSQLAnalyzer()
	for _, key := range []string{"query", "sql", "statement"} {
		if raw, ok := input.Args[key].(string); ok && strings.TrimSpace(raw) != "" {
			if sqlTool || looksLikeSQL(raw) {
				foundSQL = true
				assessment.Merge(sqlAnalyzer.AnalyzeCommand(raw))
			}
		}
	}
	if sqlTool && !foundSQL {
		assessment.Raise(SeverityMedium, RiskCategoryWrite, "SQL tool invoked without inspectable query string")
	}

	// 4. HTTP method and URL target analysis.
	c.effectiveHTTPAnalyzer().AnalyzeArgs(input, assessment)
}

func (c *DefaultSeverityClassifier) baseAssessmentFromToolAndMeta(toolName string, meta ToolMetadata) SeverityAssessment {
	lower := strings.ToLower(strings.TrimSpace(toolName))

	if meta.Destructive {
		return SeverityAssessment{
			Level:               SeverityCritical,
			Category:            RiskCategoryDestructive,
			Reasons:             []string{fmt.Sprintf("tool %q declares destructive metadata", toolName)},
			OneTimeApprovalOnly: true,
		}
	}

	if isCriticalToolName(lower) {
		return SeverityAssessment{
			Level:               SeverityCritical,
			Category:            RiskCategoryDestructive,
			Reasons:             []string{fmt.Sprintf("tool %q matches destructive operation pattern", toolName)},
			OneTimeApprovalOnly: true,
		}
	}

	if meta.ReadOnly || meta.SearchOrRead || isReadOnlyToolName(lower) {
		return SeverityAssessment{
			Level:    SeverityRead,
			Category: RiskCategoryRead,
			Reasons:  []string{fmt.Sprintf("tool %q is read-only", toolName)},
		}
	}

	if isShellToolName(lower) || isSQLToolName(lower) || isHTTPToolName(lower) {
		return SeverityAssessment{
			Level:    SeverityRead,
			Category: RiskCategoryRead,
		}
	}

	if isLowSeverityWriteToolName(lower) {
		return SeverityAssessment{
			Level:    SeverityLow,
			Category: RiskCategoryWrite,
			Reasons:  []string{fmt.Sprintf("tool %q performs workspace-scoped state update", toolName)},
		}
	}

	if isHighSeverityToolName(lower) {
		return SeverityAssessment{
			Level:    SeverityHigh,
			Category: RiskCategoryWrite,
			Reasons:  []string{fmt.Sprintf("tool %q performs high-impact external or infrastructure action", toolName)},
		}
	}

	if meta.OpenWorld {
		return SeverityAssessment{
			Level:    SeverityMedium,
			Category: RiskCategoryNetwork,
			Reasons:  []string{fmt.Sprintf("tool %q reaches external systems", toolName)},
		}
	}

	return SeverityAssessment{
		Level:    SeverityMedium,
		Category: RiskCategoryWrite,
		Reasons:  []string{fmt.Sprintf("tool %q defaults to medium write severity", toolName)},
	}
}

func isShellToolName(lower string) bool {
	return lower == "run_shell" || lower == "shell" || lower == "bash" ||
		lower == "codeexec" || lower == "workspace_exec" || lower == "hostexec" ||
		strings.HasSuffix(lower, "_shell") || strings.HasSuffix(lower, "_exec")
}

func isSQLToolName(lower string) bool {
	return strings.Contains(lower, "sql") || strings.Contains(lower, "query_db") ||
		strings.Contains(lower, "database") || strings.Contains(lower, "postgres") ||
		strings.Contains(lower, "sqlite") || strings.Contains(lower, "clickhouse")
}

func isHTTPToolName(lower string) bool {
	return lower == "http" || lower == "http_request" || lower == "http_call" ||
		lower == "rest_request" || lower == "api_request" ||
		strings.HasSuffix(lower, "_http_request")
}

func isReadOnlyToolName(lower string) bool {
	for _, exact := range []string{
		"read_file", "file_read", "list_dir", "list_directory", "glob", "grep",
		"search_tools", "tool_search", "get_tool_schema", "read_notes", "notes_index",
		"list_context", "check_budget", "memory_search", "memory_list",
		"discover_skills", "list_agents", "read_agent", "wait_for_agents",
		"tool_result_retrieve", "tool_result_query",
	} {
		if lower == exact {
			return true
		}
	}
	for _, prefix := range []string{"get_", "list_", "read_", "search_", "find_", "describe_", "view_", "inspect_"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isLowSeverityWriteToolName(lower string) bool {
	for _, exact := range []string{
		"save_file", "write_file", "file_write", "edit_file", "note",
		"delete_context", "load_skill", "unload_skill", "create_agent",
		"message_agent", "write_agent",
	} {
		if lower == exact {
			return true
		}
	}
	return false
}

func isHighSeverityToolName(lower string) bool {
	for _, sub := range []string{"install", "deploy", "merge_pull_request", "send_email", "apply", "provision"} {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

func isCriticalToolName(lower string) bool {
	for _, sub := range []string{"destroy", "drop_table", "truncate_table", "force_push", "delete_repo", "delete_cluster"} {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

func parseJSONArgumentsMap(raw []byte) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func truncateReasonValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 80 {
		return s
	}
	return s[:80] + "..."
}
