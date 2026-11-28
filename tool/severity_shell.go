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
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

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

var (
	_ CommandRiskAnalyzer = (*shellASTAnalyzer)(nil)
	_ ArgRiskAnalyzer     = (*shellASTAnalyzer)(nil)
)

// shellASTAnalyzer parses shell commands with mvdan.cc/sh/v3/syntax, unwraps
// command wrappers (such as env -i and sh -c), walks pipelines, subshells,
// redirections, and heredocs, and classifies POSIX/CLI binaries.
type shellASTAnalyzer struct {
	guard *pathGuard
}

func newShellASTAnalyzer(guard *pathGuard) *shellASTAnalyzer {
	if guard == nil {
		guard = newPathGuard("")
	}
	return &shellASTAnalyzer{guard: guard}
}

func (a *shellASTAnalyzer) pathGuard() *pathGuard {
	if a == nil || a.guard == nil {
		return newPathGuard("")
	}
	return a.guard
}

// AnalyzeArgs implements ArgRiskAnalyzer for shell execution tools.
func (a *shellASTAnalyzer) AnalyzeArgs(input SeverityInput, assessment *SeverityAssessment) {
	if assessment == nil || !isShellToolName(strings.ToLower(strings.TrimSpace(input.ToolName))) {
		return
	}
	foundShell := false
	for _, key := range []string{"command", "cmd", "script", "code"} {
		if raw, ok := input.Args[key].(string); ok && strings.TrimSpace(raw) != "" {
			foundShell = true
			assessment.Merge(a.AnalyzeCommand(raw))
		}
	}
	if !foundShell {
		assessment.Raise(SeverityMedium, RiskCategoryWrite, "shell tool invoked without inspectable command string")
	}
}

// AnalyzeCommand implements CommandRiskAnalyzer by parsing a shell script AST
// and computing the maximum operational risk across all pipeline stages,
// subshells, redirections, and heredocs. Unparseable syntax fails closed to SeverityHigh.
func (a *shellASTAnalyzer) AnalyzeCommand(command string) SeverityAssessment {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return SeverityAssessment{Level: SeverityRead, Category: RiskCategoryRead}
	}

	guard := a.pathGuard()
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	prog, err := parser.Parse(strings.NewReader(trimmed), "")
	if err != nil {
		res := SeverityAssessment{
			Level:    SeverityHigh,
			Category: RiskCategoryWrite,
			Reasons:  []string{fmt.Sprintf("shell syntax parse failed (fail-closed): %v", err)},
		}
		if guard.MatchesProtectedPath(trimmed) {
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
			a.classifyRedirect(&res, n)
			// Single-quoted heredocs (<< 'EOF') treat their body as literal data rather than executable commands.
			if (n.Op == syntax.Hdoc || n.Op == syntax.DashHdoc) && n.Word != nil && isQuotedHeredocDelimiter(n.Word) {
				return false
			}
		case *syntax.CallExpr:
			sawCommand = true
			a.classifyCallExpr(&res, n)
		}
		return true
	})

	if !sawCommand && res.Level == SeverityRead {
		res.Level = SeverityLow
		res.Category = RiskCategoryWrite
		res.Reasons = append(res.Reasons, "shell expression contains no simple command call")
	}

	return res.Finalize()
}

func (a *shellASTAnalyzer) classifyRedirect(assessment *SeverityAssessment, redir *syntax.Redirect) {
	if redir == nil || assessment == nil {
		return
	}
	guard := a.pathGuard()
	target := ""
	if redir.Word != nil {
		target = wordLiteral(redir.Word)
	}
	if target != "" && guard.MatchesProtectedPath(target) {
		assessment.Raise(SeverityCritical, RiskCategoryDestructive,
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
		if target != "" && guard.IsOutsideWorkspace(target) {
			assessment.Raise(SeverityHigh, RiskCategoryWrite,
				fmt.Sprintf("output redirect writes outside workspace (%s)", target))
			return
		}
		assessment.Raise(SeverityLow, RiskCategoryWrite,
			fmt.Sprintf("output redirect to %q mutates filesystem", target))
	}
}

func (a *shellASTAnalyzer) classifyCallExpr(assessment *SeverityAssessment, call *syntax.CallExpr) {
	if call == nil || len(call.Args) == 0 || assessment == nil {
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

	guard := a.pathGuard()
	for _, arg := range words {
		if guard.MatchesProtectedPath(arg) {
			assessment.Raise(SeverityCritical, RiskCategoryDestructive,
				fmt.Sprintf("command argument %q references protected path", truncateReasonValue(arg)))
			assessment.ProtectedPathHit = true
			assessment.OneTimeApprovalOnly = true
		}
	}

	// Unwrap leading env / command / time / nice / nohup wrappers.
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
				assessment.Merge(a.AnalyzeCommand(rest[i+1]))
				return
			}
		}
	}

	if _, ok := criticalShellCommands[bin]; ok {
		assessment.Raise(SeverityCritical, RiskCategoryDestructive,
			fmt.Sprintf("shell command %q is privileged or destructive", bin))
		assessment.OneTimeApprovalOnly = true
		return
	}

	switch bin {
	case "rm":
		a.classifyRm(assessment, rest)
		return
	case "chmod", "chown":
		a.classifyChmodChown(assessment, bin, rest)
		return
	case "find":
		for _, arg := range rest {
			if arg == "-delete" || arg == "-exec" || arg == "-execdir" {
				assessment.Raise(SeverityHigh, RiskCategoryDestructive,
					fmt.Sprintf("find with %s modifies or deletes files", arg))
				return
			}
		}
		return
	case "git":
		a.classifyGit(assessment, rest)
		return
	case "kubectl", "oc":
		a.classifyKubectl(assessment, bin, rest)
		return
	case "terraform", "tofu":
		a.classifyTerraform(assessment, bin, rest)
		return
	case "docker", "podman":
		a.classifyDocker(assessment, bin, rest)
		return
	case "npm", "pnpm", "yarn", "bun":
		a.classifyNodePkg(assessment, bin, rest)
		return
	case "go":
		a.classifyGo(assessment, rest)
		return
	case "cargo":
		a.classifyCargo(assessment, rest)
		return
	case "sed", "perl":
		for _, arg := range rest {
			if arg == "-i" || strings.HasPrefix(arg, "-i") {
				assessment.Raise(SeverityLow, RiskCategoryWrite,
					fmt.Sprintf("%s -i edits files in place", bin))
				return
			}
		}
		return
	}

	if _, ok := installShellCommands[bin]; ok {
		assessment.Raise(SeverityHigh, RiskCategoryInstall,
			fmt.Sprintf("package manager command %q installs or modifies software", bin))
		return
	}

	if _, ok := networkShellCommands[bin]; ok {
		assessment.Raise(SeverityMedium, RiskCategoryNetwork,
			fmt.Sprintf("network command %q reaches external hosts", bin))
		return
	}

	if _, ok := lowSeverityShellCommands[bin]; ok {
		assessment.Raise(SeverityLow, RiskCategoryWrite,
			fmt.Sprintf("command %q modifies local workspace files", bin))
		return
	}

	if _, ok := readOnlyShellCommands[bin]; ok {
		return
	}

	// Fail closed for unrecognized commands: at least SeverityMedium.
	assessment.Raise(SeverityMedium, RiskCategoryWrite,
		fmt.Sprintf("unrecognized shell command %q defaults to medium severity", bin))
}

func (a *shellASTAnalyzer) classifyRm(assessment *SeverityAssessment, args []string) {
	guard := a.pathGuard()
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
		if arg == "/" || arg == "/*" || arg == "~" || arg == "$HOME" || guard.IsOutsideWorkspace(arg) {
			assessment.Raise(SeverityCritical, RiskCategoryDestructive,
				fmt.Sprintf("rm targets critical or outside-workspace path %q", arg))
			assessment.OneTimeApprovalOnly = true
			return
		}
	}
	if recursive && force {
		assessment.Raise(SeverityCritical, RiskCategoryDestructive, "rm -rf performs irreversible recursive deletion")
		assessment.OneTimeApprovalOnly = true
		return
	}
	if recursive {
		assessment.Raise(SeverityHigh, RiskCategoryDestructive, "recursive rm deletes directory trees")
		return
	}
	assessment.Raise(SeverityMedium, RiskCategoryDestructive, "rm deletes files")
}

func (a *shellASTAnalyzer) classifyChmodChown(assessment *SeverityAssessment, bin string, args []string) {
	for _, arg := range args {
		if arg == "777" || arg == "a+rwx" || arg == "-R" {
			assessment.Raise(SeverityCritical, RiskCategoryDestructive,
				fmt.Sprintf("%s %s changes permissions broadly", bin, arg))
			assessment.OneTimeApprovalOnly = true
			return
		}
	}
	assessment.Raise(SeverityMedium, RiskCategoryWrite, fmt.Sprintf("%s modifies file permissions", bin))
}

func (a *shellASTAnalyzer) classifyGit(assessment *SeverityAssessment, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "", "status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "shortlog", "describe", "remote":
		for _, arg := range args {
			if arg == "set-url" || arg == "add" || arg == "remove" || arg == "rm" {
				assessment.Raise(SeverityMedium, RiskCategoryWrite, "git remote mutation")
				return
			}
		}
		return
	case "branch", "tag":
		for _, arg := range args {
			if arg == "-D" || arg == "-d" || arg == "--delete" {
				assessment.Raise(SeverityHigh, RiskCategoryDestructive, fmt.Sprintf("git %s delete", sub))
				return
			}
		}
		return
	case "add", "commit", "stash", "checkout", "switch", "merge", "rebase", "cherry-pick":
		assessment.Raise(SeverityLow, RiskCategoryWrite, fmt.Sprintf("git %s updates local repository state", sub))
		return
	case "fetch", "pull", "clone":
		assessment.Raise(SeverityMedium, RiskCategoryNetwork, fmt.Sprintf("git %s communicates with remote repository", sub))
		return
	case "push":
		for _, arg := range args {
			if arg == "--force" || arg == "-f" || strings.HasPrefix(arg, "--force-with-lease") {
				assessment.Raise(SeverityCritical, RiskCategoryDestructive, "git push --force overwrites remote history")
				assessment.OneTimeApprovalOnly = true
				return
			}
		}
		assessment.Raise(SeverityMedium, RiskCategoryNetwork, "git push publishes commits to remote")
		return
	case "reset":
		for _, arg := range args {
			if arg == "--hard" {
				assessment.Raise(SeverityCritical, RiskCategoryDestructive, "git reset --hard discards uncommitted work")
				assessment.OneTimeApprovalOnly = true
				return
			}
		}
		assessment.Raise(SeverityLow, RiskCategoryWrite, "git reset updates index/HEAD")
		return
	case "clean":
		for _, arg := range args {
			if strings.Contains(arg, "f") {
				assessment.Raise(SeverityCritical, RiskCategoryDestructive, "git clean -f permanently deletes untracked files")
				assessment.OneTimeApprovalOnly = true
				return
			}
		}
		return
	default:
		assessment.Raise(SeverityLow, RiskCategoryWrite, fmt.Sprintf("git %s subcommand", sub))
	}
}

func (a *shellASTAnalyzer) classifyKubectl(assessment *SeverityAssessment, bin string, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "get", "describe", "logs", "explain", "top", "version", "api-resources", "cluster-info", "diff":
		return
	case "delete", "drain", "cordon":
		assessment.Raise(SeverityCritical, RiskCategoryDestructive, fmt.Sprintf("%s %s removes or drains cluster resources", bin, sub))
		assessment.OneTimeApprovalOnly = true
	case "apply", "patch", "replace", "scale", "rollout", "exec", "port-forward", "edit", "set", "label", "annotate":
		assessment.Raise(SeverityHigh, RiskCategoryWrite, fmt.Sprintf("%s %s mutates live cluster state", bin, sub))
	default:
		assessment.Raise(SeverityMedium, RiskCategoryNetwork, fmt.Sprintf("%s %s interacts with cluster", bin, sub))
	}
}

func (a *shellASTAnalyzer) classifyTerraform(assessment *SeverityAssessment, bin string, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "version", "fmt", "validate", "show", "output", "providers", "graph":
		return
	case "plan":
		assessment.Raise(SeverityLow, RiskCategoryRead, fmt.Sprintf("%s plan reads infrastructure state", bin))
	case "destroy":
		assessment.Raise(SeverityCritical, RiskCategoryDestructive, fmt.Sprintf("%s destroy tears down infrastructure", bin))
		assessment.OneTimeApprovalOnly = true
	case "apply", "import", "taint", "untaint", "force-unlock", "state":
		assessment.Raise(SeverityHigh, RiskCategoryWrite, fmt.Sprintf("%s %s mutates infrastructure state", bin, sub))
	default:
		assessment.Raise(SeverityMedium, RiskCategoryWrite, fmt.Sprintf("%s %s command", bin, sub))
	}
}

func (a *shellASTAnalyzer) classifyDocker(assessment *SeverityAssessment, bin string, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "ps", "images", "inspect", "logs", "version", "info", "stats":
		return
	case "rm", "rmi", "system", "volume":
		for _, arg := range args {
			if arg == "prune" || arg == "-f" || arg == "--force" {
				assessment.Raise(SeverityCritical, RiskCategoryDestructive, fmt.Sprintf("%s %s force/prune operation", bin, sub))
				assessment.OneTimeApprovalOnly = true
				return
			}
		}
		assessment.Raise(SeverityHigh, RiskCategoryDestructive, fmt.Sprintf("%s %s removes containers/resources", bin, sub))
	default:
		assessment.Raise(SeverityHigh, RiskCategoryWrite, fmt.Sprintf("%s %s executes or modifies containers", bin, sub))
	}
}

func (a *shellASTAnalyzer) classifyNodePkg(assessment *SeverityAssessment, bin string, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "test", "lint", "typecheck", "check", "build", "list", "ls", "outdated", "why", "audit":
		assessment.Raise(SeverityLow, RiskCategoryWrite, fmt.Sprintf("%s %s runs project script", bin, sub))
	case "install", "i", "add", "remove", "uninstall", "update", "upgrade", "publish", "dlx", "exec":
		assessment.Raise(SeverityHigh, RiskCategoryInstall, fmt.Sprintf("%s %s installs or mutates packages", bin, sub))
	default:
		assessment.Raise(SeverityLow, RiskCategoryWrite, fmt.Sprintf("%s %s command", bin, sub))
	}
}

func (a *shellASTAnalyzer) classifyGo(assessment *SeverityAssessment, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "list", "version", "env", "doc", "vet":
		return
	case "test", "build", "fmt", "generate", "mod", "run", "tool":
		assessment.Raise(SeverityLow, RiskCategoryWrite, fmt.Sprintf("go %s runs local build/test", sub))
	case "install", "get":
		assessment.Raise(SeverityHigh, RiskCategoryInstall, fmt.Sprintf("go %s installs or downloads packages", sub))
	default:
		assessment.Raise(SeverityLow, RiskCategoryWrite, fmt.Sprintf("go %s command", sub))
	}
}

func (a *shellASTAnalyzer) classifyCargo(assessment *SeverityAssessment, args []string) {
	sub := firstNonFlagArg(args)
	switch sub {
	case "metadata", "tree", "version", "check", "clippy":
		return
	case "test", "build", "fmt", "bench", "doc":
		assessment.Raise(SeverityLow, RiskCategoryWrite, fmt.Sprintf("cargo %s runs local build/test", sub))
	case "install", "add", "publish":
		assessment.Raise(SeverityHigh, RiskCategoryInstall, fmt.Sprintf("cargo %s installs or publishes crates", sub))
	default:
		assessment.Raise(SeverityLow, RiskCategoryWrite, fmt.Sprintf("cargo %s command", sub))
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
	return strings.Trim(res, `"'`)
}

func firstNonFlagArg(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return strings.ToLower(a)
		}
	}
	return ""
}
