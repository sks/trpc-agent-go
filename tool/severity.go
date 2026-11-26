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
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"mvdan.cc/sh/v3/syntax"
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

// SeverityClassifier evaluates the runtime severity of a pending tool call.
type SeverityClassifier interface {
	ClassifyToolCall(ctx context.Context, req *PermissionRequest) (SeverityAssessment, error)
}

// DefaultSeverityClassifier classifies tool calls using static ToolMetadata,
// tool-name conventions, mvdan.cc/sh/v3/syntax shell AST inspection, SQL statement analysis,
// and protected-path floor checks.
type DefaultSeverityClassifier struct {
	// WorkspaceDir is the optional allowed workspace root; writes outside this directory escalate severity.
	WorkspaceDir string
	// ExtraProtectedGlobs adds host-configured protected path globs on top of DefaultProtectedPathGlobs.
	ExtraProtectedGlobs []string
}

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
	readOnlyShellCommands = map[string]struct{}{
		"ls": {}, "cat": {}, "head": {}, "tail": {}, "pwd": {}, "echo": {},
		"printf": {}, "grep": {}, "rg": {}, "egrep": {}, "fgrep": {},
		"wc": {}, "stat": {}, "file": {}, "which": {}, "whereis": {},
		"whoami": {}, "id": {}, "date": {}, "uname": {}, "hostname": {},
		"env": {}, "printenv": {}, "df": {}, "du": {}, "ps": {}, "top": {},
		"uptime": {}, "jq": {}, "yq": {}, "diff": {}, "cmp": {}, "sort": {},
		"uniq": {}, "cut": {}, "tr": {}, "basename": {}, "dirname": {},
		"realpath": {}, "readlink": {}, "true": {}, "false": {}, "test": {}, "[": {},
	}
	lowSeverityShellCommands = map[string]struct{}{
		"mkdir": {}, "touch": {}, "cp": {}, "mv": {}, "gofmt": {},
		"golangci-lint": {}, "pytest": {}, "vitest": {}, "jest": {},
	}
	networkShellCommands = map[string]struct{}{
		"curl": {}, "wget": {}, "nc": {}, "netcat": {}, "ncat": {},
		"ssh": {}, "scp": {}, "sftp": {}, "rsync": {}, "ftp": {},
		"telnet": {}, "dig": {}, "nslookup": {}, "ping": {}, "traceroute": {},
		"gh": {}, "glab": {},
	}
	installShellCommands = map[string]struct{}{
		"apt": {}, "apt-get": {}, "yum": {}, "dnf": {}, "apk": {},
		"pacman": {}, "brew": {}, "pip": {}, "pip3": {}, "pipx": {},
		"gem": {}, "rustup": {},
	}
	criticalShellCommands = map[string]struct{}{
		"sudo": {}, "su": {}, "doas": {}, "dd": {}, "mkfs": {},
		"fdisk": {}, "parted": {}, "mount": {}, "umount": {},
		"shutdown": {}, "reboot": {}, "halt": {}, "poweroff": {},
		"kill": {}, "killall": {}, "pkill": {}, "dropdb": {},
		"iptables": {}, "ufw": {}, "sysctl": {},
	}
)

// NewDefaultSeverityClassifier constructs a DefaultSeverityClassifier.
func NewDefaultSeverityClassifier(workspaceDir string, extraProtectedGlobs ...string) *DefaultSeverityClassifier {
	return &DefaultSeverityClassifier{
		WorkspaceDir:        workspaceDir,
		ExtraProtectedGlobs: extraProtectedGlobs,
	}
}

// ClassifyToolCall evaluates req and returns a SeverityAssessment.
func (c *DefaultSeverityClassifier) ClassifyToolCall(_ context.Context, req *PermissionRequest) (SeverityAssessment, error) {
	if req == nil {
		return SeverityAssessment{
			Level:    SeverityRead,
			Category: RiskCategoryRead,
		}, nil
	}

	meta := req.Metadata
	if req.Tool != nil && !meta.ReadOnly && !meta.Destructive && !meta.SearchOrRead && !meta.OpenWorld {
		meta = MetadataOf(req.Tool)
	}

	assessment := c.baseAssessmentFromToolAndMeta(req.ToolName, meta)

	argsMap := parseJSONArgumentsMap(req.Arguments)
	if len(argsMap) == 0 {
		return finalizeAssessment(assessment), nil
	}

	c.inspectArguments(&assessment, req.ToolName, argsMap)
	return finalizeAssessment(assessment), nil
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

	if isShellToolName(lower) || isSQLToolName(lower) {
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

func (c *DefaultSeverityClassifier) inspectArguments(assessment *SeverityAssessment, toolName string, args map[string]any) {
	lowerTool := strings.ToLower(strings.TrimSpace(toolName))

	// 1. Check all string leaf values for protected paths or null bytes.
	c.walkArgStrings(args, "", func(key, val string) {
		if c.matchesProtectedPath(val) {
			raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive,
				fmt.Sprintf("argument %q references protected path in %q", key, truncateReasonValue(val)))
			assessment.ProtectedPathHit = true
			assessment.OneTimeApprovalOnly = true
		}
		if isPathKey(key) && c.isOutsideWorkspace(val) && assessment.Level > SeverityRead {
			raiseAssessment(assessment, SeverityHigh, RiskCategoryWrite,
				fmt.Sprintf("path argument %q (%s) resolves outside workspace", key, truncateReasonValue(val)))
		}
	})

	// 2. Shell command AST inspection.
	if isShellToolName(lowerTool) {
		foundShell := false
		for _, key := range []string{"command", "cmd", "script", "code"} {
			if raw, ok := args[key].(string); ok && strings.TrimSpace(raw) != "" {
				foundShell = true
				shellAssess := c.ClassifyShellCommand(raw)
				mergeAssessments(assessment, shellAssess)
			}
		}
		if !foundShell {
			raiseAssessment(assessment, SeverityMedium, RiskCategoryWrite, "shell tool invoked without inspectable command string")
		}
	}

	// 3. SQL query inspection.
	foundSQL := false
	for _, key := range []string{"query", "sql", "statement"} {
		if raw, ok := args[key].(string); ok && strings.TrimSpace(raw) != "" {
			if isSQLToolName(lowerTool) || looksLikeSQL(raw) {
				foundSQL = true
				sqlAssess := classifySQLStatement(raw)
				mergeAssessments(assessment, sqlAssess)
			}
		}
	}
	if isSQLToolName(lowerTool) && !foundSQL {
		raiseAssessment(assessment, SeverityMedium, RiskCategoryWrite, "SQL tool invoked without inspectable query string")
	}
}

// ClassifyShellCommand parses a shell command with mvdan.cc/sh/v3/syntax and computes
// the highest severity across all pipeline stages, subshells, and redirections.
// Unparseable shell syntax fails closed to SeverityHigh.
func (c *DefaultSeverityClassifier) ClassifyShellCommand(command string) SeverityAssessment {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return SeverityAssessment{Level: SeverityRead, Category: RiskCategoryRead}
	}

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	prog, err := parser.Parse(strings.NewReader(trimmed), "")
	if err != nil {
		res := SeverityAssessment{
			Level:    SeverityHigh,
			Category: RiskCategoryWrite,
			Reasons:  []string{fmt.Sprintf("shell syntax parse failed (fail-closed): %v", err)},
		}
		if c.matchesProtectedPath(trimmed) {
			res.Level = SeverityCritical
			res.Category = RiskCategoryDestructive
			res.ProtectedPathHit = true
			res.OneTimeApprovalOnly = true
			res.Reasons = append(res.Reasons, "raw command references protected path")
		}
		return res
	}

	res := SeverityAssessment{
		Level:    SeverityRead,
		Category: RiskCategoryRead,
	}
	sawCommand := false

	syntax.Walk(prog, func(node syntax.Node) bool {
		if node == nil {
			return false
		}
		switch n := node.(type) {
		case *syntax.Redirect:
			c.classifyRedirect(&res, n)
			// If this is a single-quoted heredoc (<< 'EOF'), treat its body as data rather than scanning commands inside it.
			if (n.Op == syntax.Hdoc || n.Op == syntax.DashHdoc) && n.Word != nil && isQuotedHeredocDelimiter(n.Word) {
				return false
			}
		case *syntax.CallExpr:
			sawCommand = true
			c.classifyCallExpr(&res, n)
		}
		return true
	})

	if !sawCommand && res.Level == SeverityRead {
		res.Level = SeverityLow
		res.Category = RiskCategoryWrite
		res.Reasons = append(res.Reasons, "shell expression contains no simple command call")
	}

	return finalizeAssessment(res)
}

func (c *DefaultSeverityClassifier) classifyRedirect(assessment *SeverityAssessment, redir *syntax.Redirect) {
	if redir == nil {
		return
	}
	target := ""
	if redir.Word != nil {
		target = wordLiteral(redir.Word)
	}
	if target != "" && c.matchesProtectedPath(target) {
		raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive,
			fmt.Sprintf("redirection targets protected path %q", target))
		assessment.ProtectedPathHit = true
		assessment.OneTimeApprovalOnly = true
		return
	}

	switch redir.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrClob:
		if target == "/dev/null" || strings.HasPrefix(target, "&") {
			return
		}
		if target != "" && c.isOutsideWorkspace(target) {
			raiseAssessment(assessment, SeverityHigh, RiskCategoryWrite,
				fmt.Sprintf("output redirect writes outside workspace (%s)", target))
			return
		}
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite,
			fmt.Sprintf("output redirect to %q mutates filesystem", target))
	}
}

func (c *DefaultSeverityClassifier) classifyCallExpr(assessment *SeverityAssessment, call *syntax.CallExpr) {
	if call == nil || len(call.Args) == 0 {
		return
	}

	words := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		lit := strings.TrimSpace(wordLiteral(w))
		if lit != "" {
			words = append(words, lit)
		}
	}
	if len(words) == 0 {
		return
	}

	// Check every argument against protected paths.
	for _, arg := range words {
		if c.matchesProtectedPath(arg) {
			raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive,
				fmt.Sprintf("command argument %q references protected path", truncateReasonValue(arg)))
			assessment.ProtectedPathHit = true
			assessment.OneTimeApprovalOnly = true
		}
	}

	// Unwrap leading env / command / time / nice wrappers.
	cmdIdx := 0
	for cmdIdx < len(words) {
		token := filepath.Base(words[cmdIdx])
		if token == "env" || token == "command" || token == "time" || token == "nice" || token == "nohup" {
			cmdIdx++
			for cmdIdx < len(words) && (strings.HasPrefix(words[cmdIdx], "-") || strings.Contains(words[cmdIdx], "=")) {
				cmdIdx++
			}
			continue
		}
		break
	}
	if cmdIdx >= len(words) {
		return
	}

	bin := strings.ToLower(filepath.Base(words[cmdIdx]))
	rest := words[cmdIdx+1:]

	// Nested shell invocation: sh -c '...' or bash -c '...'
	if (bin == "sh" || bin == "bash" || bin == "zsh") && len(rest) >= 2 {
		for i := 0; i < len(rest)-1; i++ {
			if rest[i] == "-c" || rest[i] == "-lc" {
				subAssess := c.ClassifyShellCommand(rest[i+1])
				mergeAssessments(assessment, subAssess)
				return
			}
		}
	}

	// Check critical commands first.
	if _, ok := criticalShellCommands[bin]; ok {
		raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive,
			fmt.Sprintf("shell command %q is privileged or destructive", bin))
		assessment.OneTimeApprovalOnly = true
		return
	}

	switch bin {
	case "rm":
		c.classifyRm(assessment, rest)
		return
	case "chmod", "chown":
		c.classifyChmodChown(assessment, bin, rest)
		return
	case "find":
		for _, arg := range rest {
			if arg == "-delete" || arg == "-exec" || arg == "-execdir" {
				raiseAssessment(assessment, SeverityHigh, RiskCategoryDestructive,
					fmt.Sprintf("find with %s modifies or deletes files", arg))
				return
			}
		}
		return
	case "git":
		c.classifyGit(assessment, rest)
		return
	case "kubectl", "oc":
		c.classifyKubectl(assessment, bin, rest)
		return
	case "terraform", "tofu":
		c.classifyTerraform(assessment, bin, rest)
		return
	case "docker", "podman":
		c.classifyDocker(assessment, bin, rest)
		return
	case "npm", "pnpm", "yarn", "bun":
		c.classifyNodePkg(assessment, bin, rest)
		return
	case "go":
		c.classifyGo(assessment, rest)
		return
	case "cargo":
		c.classifyCargo(assessment, rest)
		return
	case "sed", "perl":
		for _, arg := range rest {
			if arg == "-i" || strings.HasPrefix(arg, "-i") {
				raiseAssessment(assessment, SeverityLow, RiskCategoryWrite,
					fmt.Sprintf("%s -i edits files in place", bin))
				return
			}
		}
		return
	}

	if _, ok := installShellCommands[bin]; ok {
		raiseAssessment(assessment, SeverityHigh, RiskCategoryInstall,
			fmt.Sprintf("package manager command %q installs or modifies software", bin))
		return
	}

	if _, ok := networkShellCommands[bin]; ok {
		raiseAssessment(assessment, SeverityMedium, RiskCategoryNetwork,
			fmt.Sprintf("network command %q reaches external hosts", bin))
		return
	}

	if _, ok := lowSeverityShellCommands[bin]; ok {
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite,
			fmt.Sprintf("command %q modifies local workspace files", bin))
		return
	}

	if _, ok := readOnlyShellCommands[bin]; ok {
		return
	}

	// Fail closed for unrecognized commands: at least SeverityMedium.
	raiseAssessment(assessment, SeverityMedium, RiskCategoryWrite,
		fmt.Sprintf("unrecognized shell command %q defaults to medium severity", bin))
}

func (c *DefaultSeverityClassifier) classifyRm(assessment *SeverityAssessment, args []string) {
	recursive := false
	force := false
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			if strings.ContainsAny(arg, "rR") {
				recursive = true
			}
			if strings.Contains(arg, "f") {
				force = true
			}
			continue
		}
		if arg == "--recursive" {
			recursive = true
			continue
		}
		if arg == "--force" {
			force = true
			continue
		}
		if arg == "/" || arg == "/*" || arg == "~" || arg == "$HOME" || c.isOutsideWorkspace(arg) {
			raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive,
				fmt.Sprintf("rm targets critical or outside-workspace path %q", arg))
			assessment.OneTimeApprovalOnly = true
			return
		}
	}
	if recursive && force {
		raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive, "rm -rf performs irreversible recursive deletion")
		assessment.OneTimeApprovalOnly = true
		return
	}
	if recursive {
		raiseAssessment(assessment, SeverityHigh, RiskCategoryDestructive, "recursive rm deletes directory trees")
		return
	}
	raiseAssessment(assessment, SeverityMedium, RiskCategoryDestructive, "rm deletes files")
}

func (c *DefaultSeverityClassifier) classifyChmodChown(assessment *SeverityAssessment, bin string, args []string) {
	for _, arg := range args {
		if arg == "777" || arg == "a+rwx" || arg == "-R" {
			raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive,
				fmt.Sprintf("%s %s changes permissions broadly", bin, arg))
			assessment.OneTimeApprovalOnly = true
			return
		}
	}
	raiseAssessment(assessment, SeverityMedium, RiskCategoryWrite, fmt.Sprintf("%s modifies file permissions", bin))
}

func (c *DefaultSeverityClassifier) classifyGit(assessment *SeverityAssessment, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "", "status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "shortlog", "describe", "remote":
		for _, a := range args {
			if a == "set-url" || a == "add" || a == "remove" || a == "rm" {
				raiseAssessment(assessment, SeverityMedium, RiskCategoryWrite, "git remote mutation")
				return
			}
		}
		return
	case "branch", "tag":
		for _, a := range args {
			if a == "-D" || a == "-d" || a == "--delete" {
				raiseAssessment(assessment, SeverityHigh, RiskCategoryDestructive, fmt.Sprintf("git %s delete", sub))
				return
			}
		}
		return
	case "add", "commit", "stash", "checkout", "switch", "merge", "rebase", "cherry-pick":
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite, fmt.Sprintf("git %s updates local repository state", sub))
		return
	case "fetch", "pull", "clone":
		raiseAssessment(assessment, SeverityMedium, RiskCategoryNetwork, fmt.Sprintf("git %s communicates with remote repository", sub))
		return
	case "push":
		for _, a := range args {
			if a == "--force" || a == "-f" || strings.HasPrefix(a, "--force-with-lease") {
				raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive, "git push --force overwrites remote history")
				assessment.OneTimeApprovalOnly = true
				return
			}
		}
		raiseAssessment(assessment, SeverityMedium, RiskCategoryNetwork, "git push publishes commits to remote")
		return
	case "reset":
		for _, a := range args {
			if a == "--hard" {
				raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive, "git reset --hard discards uncommitted work")
				assessment.OneTimeApprovalOnly = true
				return
			}
		}
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite, "git reset updates index/HEAD")
		return
	case "clean":
		for _, a := range args {
			if strings.Contains(a, "f") {
				raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive, "git clean -f permanently deletes untracked files")
				assessment.OneTimeApprovalOnly = true
				return
			}
		}
		return
	default:
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite, fmt.Sprintf("git %s subcommand", sub))
	}
}

func (c *DefaultSeverityClassifier) classifyKubectl(assessment *SeverityAssessment, bin string, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "get", "describe", "logs", "explain", "top", "version", "api-resources", "cluster-info", "diff":
		return
	case "delete", "drain", "cordon":
		raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive, fmt.Sprintf("%s %s removes or drains cluster resources", bin, sub))
		assessment.OneTimeApprovalOnly = true
	case "apply", "patch", "replace", "scale", "rollout", "exec", "port-forward", "edit", "set", "label", "annotate":
		raiseAssessment(assessment, SeverityHigh, RiskCategoryWrite, fmt.Sprintf("%s %s mutates live cluster state", bin, sub))
	default:
		raiseAssessment(assessment, SeverityMedium, RiskCategoryNetwork, fmt.Sprintf("%s %s interacts with cluster", bin, sub))
	}
}

func (c *DefaultSeverityClassifier) classifyTerraform(assessment *SeverityAssessment, bin string, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "version", "fmt", "validate", "show", "output", "providers", "graph":
		return
	case "plan":
		raiseAssessment(assessment, SeverityLow, RiskCategoryRead, fmt.Sprintf("%s plan reads infrastructure state", bin))
	case "destroy":
		raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive, fmt.Sprintf("%s destroy tears down infrastructure", bin))
		assessment.OneTimeApprovalOnly = true
	case "apply", "import", "taint", "untaint", "force-unlock", "state":
		raiseAssessment(assessment, SeverityHigh, RiskCategoryWrite, fmt.Sprintf("%s %s mutates infrastructure state", bin, sub))
	default:
		raiseAssessment(assessment, SeverityMedium, RiskCategoryWrite, fmt.Sprintf("%s %s command", bin, sub))
	}
}

func (c *DefaultSeverityClassifier) classifyDocker(assessment *SeverityAssessment, bin string, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "ps", "images", "inspect", "logs", "version", "info", "stats":
		return
	case "rm", "rmi", "system", "volume":
		for _, a := range args {
			if a == "prune" || a == "-f" || a == "--force" {
				raiseAssessment(assessment, SeverityCritical, RiskCategoryDestructive, fmt.Sprintf("%s %s force/prune operation", bin, sub))
				assessment.OneTimeApprovalOnly = true
				return
			}
		}
		raiseAssessment(assessment, SeverityHigh, RiskCategoryDestructive, fmt.Sprintf("%s %s removes containers/resources", bin, sub))
	default:
		raiseAssessment(assessment, SeverityHigh, RiskCategoryWrite, fmt.Sprintf("%s %s executes or modifies containers", bin, sub))
	}
}

func (c *DefaultSeverityClassifier) classifyNodePkg(assessment *SeverityAssessment, bin string, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "test", "lint", "typecheck", "check", "build", "list", "ls", "outdated", "why", "audit":
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite, fmt.Sprintf("%s %s runs project script", bin, sub))
	case "install", "i", "add", "remove", "uninstall", "update", "upgrade", "publish", "dlx", "exec":
		raiseAssessment(assessment, SeverityHigh, RiskCategoryInstall, fmt.Sprintf("%s %s installs or mutates packages", bin, sub))
	default:
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite, fmt.Sprintf("%s %s command", bin, sub))
	}
}

func (c *DefaultSeverityClassifier) classifyGo(assessment *SeverityAssessment, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "list", "version", "env", "doc", "vet":
		return
	case "test", "build", "fmt", "generate", "mod", "run", "tool":
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite, fmt.Sprintf("go %s runs local build/test", sub))
	case "install", "get":
		raiseAssessment(assessment, SeverityHigh, RiskCategoryInstall, fmt.Sprintf("go %s installs or downloads packages", sub))
	default:
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite, fmt.Sprintf("go %s command", sub))
	}
}

func (c *DefaultSeverityClassifier) classifyCargo(assessment *SeverityAssessment, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "metadata", "tree", "version", "check", "clippy":
		return
	case "test", "build", "fmt", "bench", "doc":
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite, fmt.Sprintf("cargo %s runs local build/test", sub))
	case "install", "add", "publish":
		raiseAssessment(assessment, SeverityHigh, RiskCategoryInstall, fmt.Sprintf("cargo %s installs or publishes crates", sub))
	default:
		raiseAssessment(assessment, SeverityLow, RiskCategoryWrite, fmt.Sprintf("cargo %s command", sub))
	}
}

func classifySQLStatement(sql string) SeverityAssessment {
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
		hasWhere := false
		for _, tok := range fields[1:] {
			if tok == "WHERE" {
				hasWhere = true
				break
			}
		}
		if !hasWhere {
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
		hasWhere := false
		for _, tok := range fields[1:] {
			if tok == "WHERE" {
				hasWhere = true
				break
			}
		}
		if !hasWhere {
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

func (c *DefaultSeverityClassifier) matchesProtectedPath(val string) bool {
	if strings.ContainsRune(val, '\x00') {
		return true
	}
	normalized := filepath.ToSlash(strings.TrimSpace(val))
	if normalized == "" {
		return false
	}

	globs := make([]string, 0, len(DefaultProtectedPathGlobs)+len(c.ExtraProtectedGlobs))
	globs = append(globs, DefaultProtectedPathGlobs...)
	globs = append(globs, c.ExtraProtectedGlobs...)

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

func (c *DefaultSeverityClassifier) isOutsideWorkspace(pathVal string) bool {
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
	if c.WorkspaceDir == "" {
		return filepath.IsAbs(trimmed)
	}
	if !filepath.IsAbs(trimmed) {
		return false
	}
	absWorkspace, err := filepath.Abs(c.WorkspaceDir)
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

func (c *DefaultSeverityClassifier) walkArgStrings(v any, key string, visit func(key, val string)) {
	switch typed := v.(type) {
	case map[string]any:
		for k, child := range typed {
			c.walkArgStrings(child, k, visit)
		}
	case []any:
		for _, child := range typed {
			c.walkArgStrings(child, key, visit)
		}
	case string:
		visit(key, typed)
	}
}

func isQuotedHeredocDelimiter(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	for _, part := range w.Parts {
		switch part.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			return true
		}
	}
	return false
}

func wordLiteral(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	printer := syntax.NewPrinter()
	_ = printer.Print(&b, w)
	res := strings.TrimSpace(b.String())
	res = strings.Trim(res, `"'`)
	return res
}

func firstNonFlagArg(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return strings.ToLower(a)
		}
	}
	return ""
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

func raiseAssessment(target *SeverityAssessment, level SeverityLevel, category RiskCategory, reason string) {
	if target == nil {
		return
	}
	if level > target.Level {
		target.Level = level
		target.Category = category
	}
	if level == SeverityCritical {
		target.OneTimeApprovalOnly = true
	}
	if reason != "" {
		for _, existing := range target.Reasons {
			if existing == reason {
				return
			}
		}
		target.Reasons = append(target.Reasons, reason)
	}
}

func mergeAssessments(target *SeverityAssessment, other SeverityAssessment) {
	if target == nil {
		return
	}
	if other.Level > target.Level {
		target.Level = other.Level
		target.Category = other.Category
	}
	if other.OneTimeApprovalOnly {
		target.OneTimeApprovalOnly = true
	}
	if other.ProtectedPathHit {
		target.ProtectedPathHit = true
	}
	for _, r := range other.Reasons {
		raiseAssessment(target, target.Level, target.Category, r)
	}
}

func finalizeAssessment(a SeverityAssessment) SeverityAssessment {
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

func truncateReasonValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 80 {
		return s
	}
	return s[:80] + "..."
}
