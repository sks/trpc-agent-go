//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package tool

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// DefaultProtectedPathGlobs are credential stores and system roots that always trigger SeverityCritical.
var DefaultProtectedPathGlobs = []string{
	"**/.ssh/**",
	"**/.ssh",
	"**/.gnupg/**",
	"**/.gnupg",
	"**/.aws/**",
	"**/.aws",
	"**/.kube/**",
	"**/.docker/config.json",
	"**/.env",
	"**/.env.*",
	"**/id_rsa*",
	"**/id_ed25519*",
	"/etc/shadow",
	"/etc/sudoers*",
	"/etc/passwd",
}

var (
	_ ArgRiskAnalyzer     = (*pathGuard)(nil)
	_ CommandRiskAnalyzer = (*sqlRiskAnalyzer)(nil)
	_ ArgRiskAnalyzer     = (*sqlRiskAnalyzer)(nil)
	_ ArgRiskAnalyzer     = (*httpRiskAnalyzer)(nil)
)

// pathGuard checks arguments against protected credential/system globs and
// workspace directory boundaries.
type pathGuard struct {
	workspaceDir        string
	extraProtectedGlobs []string
}

func newPathGuard(workspaceDir string, extraProtectedGlobs ...string) *pathGuard {
	return &pathGuard{
		workspaceDir:        workspaceDir,
		extraProtectedGlobs: extraProtectedGlobs,
	}
}

// AnalyzeArgs implements ArgRiskAnalyzer by scanning string leaves for protected
// paths and outside-workspace write paths.
func (g *pathGuard) AnalyzeArgs(input SeverityInput, assessment *SeverityAssessment) {
	if g == nil || assessment == nil || len(input.Args) == 0 {
		return
	}
	walkArgStrings(input.Args, "", func(key, val string) {
		if g.MatchesProtectedPath(val) {
			assessment.Raise(SeverityCritical, RiskCategoryDestructive,
				fmt.Sprintf("argument %q references protected path in %q", key, truncateReasonValue(val)))
			assessment.ProtectedPathHit = true
			assessment.OneTimeApprovalOnly = true
		}
		if isPathKey(key) && g.IsOutsideWorkspace(val) && assessment.Level > SeverityRead {
			assessment.Raise(SeverityHigh, RiskCategoryWrite,
				fmt.Sprintf("path argument %q (%s) resolves outside workspace", key, truncateReasonValue(val)))
		}
	})
}

// MatchesProtectedPath reports whether val references any protected path glob or null byte.
func (g *pathGuard) MatchesProtectedPath(val string) bool {
	if strings.ContainsRune(val, '\x00') {
		return true
	}
	normalized := filepath.ToSlash(strings.TrimSpace(val))
	if normalized == "" {
		return false
	}

	var extra []string
	if g != nil {
		extra = g.extraProtectedGlobs
	}
	globs := make([]string, 0, len(DefaultProtectedPathGlobs)+len(extra))
	globs = append(globs, DefaultProtectedPathGlobs...)
	globs = append(globs, extra...)

	tokens := strings.FieldsFunc(normalized, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '"' || r == '\'' || r == ';' || r == ':'
	})
	tokens = append(tokens, normalized)

	for _, candidate := range tokens {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		cleaned := filepath.ToSlash(filepath.Clean(candidate))
		for _, pattern := range globs {
			if matched, _ := doublestar.Match(pattern, candidate); matched {
				return true
			}
			if matched, _ := doublestar.Match(pattern, cleaned); matched {
				return true
			}
			if strings.HasPrefix(pattern, "**/") {
				trimmedPattern := strings.TrimPrefix(pattern, "**/")
				if matched, _ := doublestar.Match(trimmedPattern, candidate); matched {
					return true
				}
				if matched, _ := doublestar.Match(trimmedPattern, strings.TrimPrefix(cleaned, "~/")); matched {
					return true
				}
			}
		}
	}
	return false
}

// IsOutsideWorkspace reports whether pathVal escapes the configured workspace root.
func (g *pathGuard) IsOutsideWorkspace(pathVal string) bool {
	trimmed := strings.TrimSpace(pathVal)
	if trimmed == "" {
		return false
	}
	cleaned := filepath.ToSlash(filepath.Clean(trimmed))
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return true
	}
	if strings.HasPrefix(trimmed, "~") {
		return true
	}
	workspaceDir := ""
	if g != nil {
		workspaceDir = g.workspaceDir
	}
	if workspaceDir == "" {
		return filepath.IsAbs(trimmed)
	}
	if !filepath.IsAbs(trimmed) {
		return false
	}
	absWorkspace, err := filepath.Abs(workspaceDir)
	if err != nil {
		return true
	}
	absTarget, err := filepath.Abs(trimmed)
	if err != nil {
		return true
	}
	rel, err := filepath.Rel(absWorkspace, absTarget)
	if err != nil {
		return true
	}
	relSlash := filepath.ToSlash(rel)
	return relSlash == ".." || strings.HasPrefix(relSlash, "../")
}

// sqlRiskAnalyzer classifies SQL statements by verb, CTE mutation keywords,
// and presence of a WHERE clause on UPDATE/DELETE statements.
type sqlRiskAnalyzer struct{}

func newSQLRiskAnalyzer() *sqlRiskAnalyzer {
	return &sqlRiskAnalyzer{}
}

// AnalyzeArgs implements ArgRiskAnalyzer for SQL tools and SQL-like string arguments.
func (a *sqlRiskAnalyzer) AnalyzeArgs(input SeverityInput, assessment *SeverityAssessment) {
	if assessment == nil {
		return
	}
	lowerTool := strings.ToLower(strings.TrimSpace(input.ToolName))
	sqlTool := isSQLToolName(lowerTool)
	foundSQL := false
	for _, key := range []string{"query", "sql", "statement"} {
		if raw, ok := input.Args[key].(string); ok && strings.TrimSpace(raw) != "" {
			if sqlTool || looksLikeSQL(raw) {
				foundSQL = true
				assessment.Merge(a.AnalyzeCommand(raw))
			}
		}
	}
	if sqlTool && !foundSQL {
		assessment.Raise(SeverityMedium, RiskCategoryWrite, "SQL tool invoked without inspectable query string")
	}
}

// AnalyzeCommand implements CommandRiskAnalyzer for SQL queries.
func (a *sqlRiskAnalyzer) AnalyzeCommand(sql string) SeverityAssessment {
	fields := strings.Fields(strings.ToUpper(strings.TrimSpace(sql)))
	if len(fields) == 0 {
		return SeverityAssessment{Level: SeverityRead, Category: RiskCategoryRead}
	}
	verb := fields[0]
	switch verb {
	case "SELECT", "EXPLAIN", "SHOW", "DESCRIBE", "DESC", "PRAGMA", "WITH":
		for _, tok := range fields[1:] {
			if tok == "DELETE" || tok == "DROP" || tok == "TRUNCATE" || tok == "UPDATE" || tok == "INSERT" {
				return SeverityAssessment{
					Level:    SeverityHigh,
					Category: RiskCategoryWrite,
					Reasons:  []string{fmt.Sprintf("CTE SQL statement contains mutating keyword %s", tok)},
				}
			}
		}
		return SeverityAssessment{
			Level:    SeverityRead,
			Category: RiskCategoryRead,
			Reasons:  []string{fmt.Sprintf("read-only SQL %s query", verb)},
		}
	case "INSERT", "UPSERT", "REPLACE", "MERGE":
		return SeverityAssessment{
			Level:    SeverityMedium,
			Category: RiskCategoryWrite,
			Reasons:  []string{fmt.Sprintf("SQL %s writes rows", verb)},
		}
	case "UPDATE":
		if !containsSQLToken(fields[1:], "WHERE") {
			return SeverityAssessment{
				Level:               SeverityCritical,
				Category:            RiskCategoryDestructive,
				Reasons:             []string{"SQL UPDATE without WHERE clause modifies entire table"},
				OneTimeApprovalOnly: true,
			}
		}
		return SeverityAssessment{
			Level:    SeverityMedium,
			Category: RiskCategoryWrite,
			Reasons:  []string{"SQL UPDATE with WHERE clause"},
		}
	case "DELETE":
		if !containsSQLToken(fields[1:], "WHERE") {
			return SeverityAssessment{
				Level:               SeverityCritical,
				Category:            RiskCategoryDestructive,
				Reasons:             []string{"SQL DELETE without WHERE clause deletes entire table"},
				OneTimeApprovalOnly: true,
			}
		}
		return SeverityAssessment{
			Level:    SeverityHigh,
			Category: RiskCategoryDestructive,
			Reasons:  []string{"SQL DELETE with WHERE clause removes rows"},
		}
	case "DROP", "TRUNCATE":
		return SeverityAssessment{
			Level:               SeverityCritical,
			Category:            RiskCategoryDestructive,
			Reasons:             []string{fmt.Sprintf("SQL %s is destructive and irreversible", verb)},
			OneTimeApprovalOnly: true,
		}
	case "ALTER", "GRANT", "REVOKE", "CREATE":
		return SeverityAssessment{
			Level:    SeverityHigh,
			Category: RiskCategoryWrite,
			Reasons:  []string{fmt.Sprintf("SQL DDL/DCL statement %s", verb)},
		}
	default:
		return SeverityAssessment{
			Level:    SeverityMedium,
			Category: RiskCategoryWrite,
			Reasons:  []string{fmt.Sprintf("SQL statement starting with %s", verb)},
		}
	}
}

// httpRiskAnalyzer inspects HTTP method and target URL arguments for mutating
// verbs, destructive DELETE requests, local file:// schemes, and cloud metadata SSRF targets.
type httpRiskAnalyzer struct{}

func newHTTPRiskAnalyzer() *httpRiskAnalyzer {
	return &httpRiskAnalyzer{}
}

// AnalyzeArgs implements ArgRiskAnalyzer for HTTP/REST tool invocations and URL arguments.
func (a *httpRiskAnalyzer) AnalyzeArgs(input SeverityInput, assessment *SeverityAssessment) {
	if assessment == nil || len(input.Args) == 0 {
		return
	}

	rawURL := firstStringArg(input.Args, "url", "uri", "endpoint")
	rawMethod := firstStringArg(input.Args, "method", "http_method")
	httpTool := isHTTPToolName(strings.ToLower(strings.TrimSpace(input.ToolName)))

	if rawURL != "" {
		if urlAssess, risky := classifyURLTarget(rawURL); risky {
			assessment.Merge(urlAssess)
		}
	}

	if !httpTool && (rawMethod == "" || rawURL == "") {
		return
	}
	if httpTool && rawURL == "" && rawMethod == "" {
		assessment.Raise(SeverityMedium, RiskCategoryNetwork, "HTTP tool invoked without inspectable URL or method")
		return
	}
	assessment.Merge(a.AnalyzeHTTP(rawMethod, rawURL))
}

// AnalyzeHTTP classifies an HTTP method and URL pair.
func (a *httpRiskAnalyzer) AnalyzeHTTP(method, rawURL string) SeverityAssessment {
	res := SeverityAssessment{
		Level:    SeverityRead,
		Category: RiskCategoryRead,
	}
	if rawURL != "" {
		if urlAssess, risky := classifyURLTarget(rawURL); risky {
			res.Merge(urlAssess)
		}
	}

	verb := strings.ToUpper(strings.TrimSpace(method))
	switch verb {
	case "", "GET", "HEAD", "OPTIONS":
		if res.Level == SeverityRead {
			res.Reasons = append(res.Reasons, fmt.Sprintf("read-only HTTP %s request", defaultIfEmpty(verb, "GET")))
		}
	case "POST", "PUT", "PATCH":
		res.Raise(SeverityMedium, RiskCategoryNetwork, fmt.Sprintf("mutating HTTP %s request", verb))
	case "DELETE":
		res.Raise(SeverityHigh, RiskCategoryDestructive, "destructive HTTP DELETE request")
	default:
		res.Raise(SeverityMedium, RiskCategoryNetwork, fmt.Sprintf("HTTP %s request", verb))
	}
	return res.Finalize()
}

func classifyURLTarget(rawURL string) (SeverityAssessment, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return SeverityAssessment{}, false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "file" {
		return SeverityAssessment{
			Level:               SeverityCritical,
			Category:            RiskCategoryDestructive,
			Reasons:             []string{"file:// URL scheme accesses local filesystem"},
			ProtectedPathHit:    true,
			OneTimeApprovalOnly: true,
		}, true
	}
	host := strings.ToLower(parsed.Hostname())
	switch host {
	case "169.254.169.254", "metadata.google.internal", "100.100.100.200", "fd00:ec2::254":
		return SeverityAssessment{
			Level:               SeverityCritical,
			Category:            RiskCategoryDestructive,
			Reasons:             []string{fmt.Sprintf("URL targets cloud instance metadata service %q", host)},
			ProtectedPathHit:    true,
			OneTimeApprovalOnly: true,
		}, true
	}
	return SeverityAssessment{}, false
}

func containsSQLToken(tokens []string, target string) bool {
	for _, tok := range tokens {
		if tok == target {
			return true
		}
	}
	return false
}

func looksLikeSQL(s string) bool {
	upper := strings.ToUpper(strings.TrimSpace(s))
	for _, prefix := range []string{"SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "TRUNCATE ", "ALTER ", "CREATE TABLE"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func isPathKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	return k == "path" || k == "file_path" || k == "filepath" || k == "file" ||
		k == "target" || k == "destination" || k == "dest" || k == "dir" || k == "directory"
}

func firstStringArg(args map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := args[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func defaultIfEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func walkArgStrings(v any, key string, visit func(key, val string)) {
	switch typed := v.(type) {
	case map[string]any:
		for k, child := range typed {
			walkArgStrings(child, k, visit)
		}
	case []any:
		for _, child := range typed {
			walkArgStrings(child, key, visit)
		}
	case string:
		visit(key, typed)
	}
}
