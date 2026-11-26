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
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// RuleEffect specifies the policy action of a matching ToolRule.
type RuleEffect string

const (
	// RuleEffectAllow permits the tool to be advertised, searched, and executed (subject to severity tier).
	RuleEffectAllow RuleEffect = "allow"
	// RuleEffectDeny blocks the tool across wire schemas, tool_search, and execution.
	RuleEffectDeny RuleEffect = "deny"
	// RuleEffectHide omits the tool from initial wire schemas while keeping it callable (e.g. via call_tool).
	RuleEffectHide RuleEffect = "hide"
	// RuleEffectRequireApproval forces a permission ask before execution regardless of autonomy tier.
	RuleEffectRequireApproval RuleEffect = "require_approval"
	// RuleEffectAutoApprove waives approval prompts for matching non-critical tool calls.
	RuleEffectAutoApprove RuleEffect = "auto_approve"
)

// AutonomyLevel configures the baseline severity gate for a session or agent.
type AutonomyLevel string

const (
	// AutonomyReadOnly allows SeverityRead and denies all mutating calls (SeverityLow..Critical).
	AutonomyReadOnly AutonomyLevel = "readonly"
	// AutonomySupervised auto-approves SeverityRead and SeverityLow, prompts for Medium/High, and forces one-time prompt for Critical.
	AutonomySupervised AutonomyLevel = "supervised"
	// AutonomyFull auto-approves SeverityRead..Medium, prompts for High/Critical.
	AutonomyFull AutonomyLevel = "full"
)

// RuleLayer identifies which policy tier a rule belongs to.
type RuleLayer string

const (
	// RuleLayerOperator is the global operator layer from config.toml (applies to all agents and sub-agents).
	RuleLayerOperator RuleLayer = "operator"
	// RuleLayerArchetype is the primary agent definition layer.
	RuleLayerArchetype RuleLayer = "archetype"
	// RuleLayerSubAgent is the delegated sub-agent layer (inherits operator rules, not parent planner-only denials).
	RuleLayerSubAgent RuleLayer = "subagent"
)

// ToolRuleMatch defines glob and severity match predicates for a ToolRule.
type ToolRuleMatch struct {
	// Name matches the tool name using case-insensitive glob syntax (e.g. "mcp__github__*", "gmail_*").
	Name string `json:"name,omitempty" yaml:"name,omitempty" toml:"name,omitempty"`
	// Family matches the tool's integration prefix before the first underscore (e.g. "github", "slack").
	Family string `json:"family,omitempty" yaml:"family,omitempty" toml:"family,omitempty"`
	// Category matches the computed RiskCategory ("read", "write", "network", "install", "destructive").
	Category RiskCategory `json:"category,omitempty" yaml:"category,omitempty" toml:"category,omitempty"`
	// MinSeverity matches when the computed SeverityLevel is >= MinSeverity.
	MinSeverity *SeverityLevel `json:"min_severity,omitempty" yaml:"min_severity,omitempty" toml:"min_severity,omitempty"`
}

// ToolRuleWhen restricts a rule to a specific runtime context.
type ToolRuleWhen struct {
	// Channel matches the active messaging channel (e.g. "slack", "telegram", "web").
	Channel string `json:"channel,omitempty" yaml:"channel,omitempty" toml:"channel,omitempty"`
	// Agent matches the active agent name or archetype.
	Agent string `json:"agent,omitempty" yaml:"agent,omitempty" toml:"agent,omitempty"`
	// Origin matches the turn origin (e.g. "interactive_user", "local_schedule", "external_trigger").
	Origin string `json:"origin,omitempty" yaml:"origin,omitempty" toml:"origin,omitempty"`
}

// ToolRule is one declarative tool governance rule.
type ToolRule struct {
	ID     string         `json:"id,omitempty" yaml:"id,omitempty" toml:"id,omitempty"`
	Effect RuleEffect     `json:"effect" yaml:"effect" toml:"effect"`
	Match  ToolRuleMatch  `json:"match" yaml:"match" toml:"match"`
	Except *ToolRuleMatch `json:"except,omitempty" yaml:"except,omitempty" toml:"except,omitempty"`
	When   *ToolRuleWhen  `json:"when,omitempty" yaml:"when,omitempty" toml:"when,omitempty"`
	Reason string         `json:"reason,omitempty" yaml:"reason,omitempty" toml:"reason,omitempty"`
}

// RuleRuntimeContext supplies caller context (channel, agent, origin) during rule evaluation.
type RuleRuntimeContext struct {
	Channel string
	Agent   string
	Origin  string
}

type ruleRuntimeContextKey struct{}

// WithRuleRuntimeContext attaches a RuleRuntimeContext to ctx.
func WithRuleRuntimeContext(ctx context.Context, rc RuleRuntimeContext) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, ruleRuntimeContextKey{}, rc)
}

// RuleRuntimeContextFrom retrieves the RuleRuntimeContext from ctx.
func RuleRuntimeContextFrom(ctx context.Context) RuleRuntimeContext {
	if ctx == nil {
		return RuleRuntimeContext{}
	}
	rc, _ := ctx.Value(ruleRuntimeContextKey{}).(RuleRuntimeContext)
	return rc
}

// RuleLayerSet holds the rules belonging to one RuleLayer.
type RuleLayerSet struct {
	Layer RuleLayer
	Rules []ToolRule
}

// RuleEvaluationResult describes the outcome of evaluating the 3-layer rule stack and severity gate.
type RuleEvaluationResult struct {
	Decision   PermissionDecision
	Effect     RuleEffect
	RuleID     string
	Layer      RuleLayer
	Assessment SeverityAssessment
}

// RulePermissionPolicy evaluates 3-layer declarative tool rules plus severity-based autonomy gating.
type RulePermissionPolicy struct {
	Autonomy   AutonomyLevel
	Classifier SeverityClassifier
	Layers     []RuleLayerSet
}

// NewRulePermissionPolicy creates a RulePermissionPolicy for the given autonomy tier, classifier, and rule layers.
func NewRulePermissionPolicy(autonomy AutonomyLevel, classifier SeverityClassifier, layers ...RuleLayerSet) *RulePermissionPolicy {
	if autonomy == "" {
		autonomy = AutonomySupervised
	}
	if classifier == nil {
		classifier = NewDefaultSeverityClassifier("")
	}
	return &RulePermissionPolicy{
		Autonomy:   autonomy,
		Classifier: classifier,
		Layers:     layers,
	}
}

// ForSubAgent derives a child RulePermissionPolicy that retains the Operator layer
// and replaces the Archetype layer with the sub-agent's own rule layer.
func (p *RulePermissionPolicy) ForSubAgent(subAgentRules []ToolRule) *RulePermissionPolicy {
	if p == nil {
		return NewRulePermissionPolicy(AutonomySupervised, nil, RuleLayerSet{
			Layer: RuleLayerSubAgent,
			Rules: subAgentRules,
		})
	}
	var nextLayers []RuleLayerSet
	for _, layer := range p.Layers {
		if layer.Layer == RuleLayerOperator {
			nextLayers = append(nextLayers, layer)
		}
	}
	if len(subAgentRules) > 0 {
		nextLayers = append(nextLayers, RuleLayerSet{
			Layer: RuleLayerSubAgent,
			Rules: subAgentRules,
		})
	}
	return &RulePermissionPolicy{
		Autonomy:   p.Autonomy,
		Classifier: p.Classifier,
		Layers:     nextLayers,
	}
}

// IsVisibleOnWire reports whether toolName should be advertised in Request.Tools.
// Tools matched by a deny or hide rule are excluded from the wire schema.
func (p *RulePermissionPolicy) IsVisibleOnWire(ctx context.Context, toolName string) bool {
	if p == nil {
		return true
	}
	rc := RuleRuntimeContextFrom(ctx)
	for _, layer := range p.Layers {
		effect, _ := evaluateLayerNameOnly(layer, toolName, rc)
		if effect == RuleEffectDeny || effect == RuleEffectHide {
			return false
		}
	}
	return true
}

// IsSearchable reports whether toolName may appear in tool_search results.
// Denied tools are never searchable; hidden tools remain searchable/callable via call_tool unless denied.
func (p *RulePermissionPolicy) IsSearchable(ctx context.Context, toolName string) bool {
	if p == nil {
		return true
	}
	rc := RuleRuntimeContextFrom(ctx)
	for _, layer := range p.Layers {
		effect, _ := evaluateLayerNameOnly(layer, toolName, rc)
		if effect == RuleEffectDeny {
			return false
		}
	}
	return true
}

// Evaluate runs full rule + severity evaluation and returns the detailed RuleEvaluationResult.
func (p *RulePermissionPolicy) Evaluate(ctx context.Context, req *PermissionRequest) (RuleEvaluationResult, error) {
	if p == nil || req == nil {
		return RuleEvaluationResult{
			Decision: AllowPermission(),
			Effect:   RuleEffectAllow,
		}, nil
	}

	classifier := p.Classifier
	if classifier == nil {
		classifier = NewDefaultSeverityClassifier("")
	}
	assessment, err := classifier.ClassifyToolCall(ctx, req)
	if err != nil {
		return RuleEvaluationResult{}, err
	}

	rc := RuleRuntimeContextFrom(ctx)
	// Escalate severity for untrusted external triggers.
	if strings.EqualFold(rc.Origin, "external_trigger") && assessment.Level > SeverityRead && assessment.Level < SeverityCritical {
		assessment.Level++
		assessment.Reasons = append(assessment.Reasons, "severity escalated +1 tier for external_trigger origin")
	}

	// Protected-path floor cannot be overridden by auto_approve rules.
	if assessment.ProtectedPathHit {
		reason := fmt.Sprintf("[operator:protected-path-floor] blocked by protected-path floor (%s)", strings.Join(assessment.Reasons, "; "))
		return RuleEvaluationResult{
			Decision:   DenyPermission(reason),
			Effect:     RuleEffectDeny,
			RuleID:     "protected-path-floor",
			Layer:      RuleLayerOperator,
			Assessment: assessment,
		}, nil
	}

	var winningEffect RuleEffect
	var winningRule ToolRule
	var winningLayer RuleLayer

	for _, layer := range p.Layers {
		effect, rule := evaluateLayerFull(layer, req.ToolName, assessment, rc)
		if effect == RuleEffectDeny {
			reason := formatRuleReason(rule, layer.Layer, "denied by tool rule")
			return RuleEvaluationResult{
				Decision:   DenyPermission(reason),
				Effect:     RuleEffectDeny,
				RuleID:     rule.ID,
				Layer:      layer.Layer,
				Assessment: assessment,
			}, nil
		}
		if effect == RuleEffectRequireApproval {
			winningEffect = RuleEffectRequireApproval
			winningRule = rule
			winningLayer = layer.Layer
		}
		if effect == RuleEffectAutoApprove && winningEffect != RuleEffectRequireApproval && !assessment.OneTimeApprovalOnly {
			winningEffect = RuleEffectAutoApprove
			winningRule = rule
			winningLayer = layer.Layer
		}
	}

	if winningEffect == RuleEffectRequireApproval {
		reason := formatRuleReason(winningRule, winningLayer,
			fmt.Sprintf("approval required by rule (severity=%s)", assessment.Level))
		return RuleEvaluationResult{
			Decision:   AskPermission(reason),
			Effect:     RuleEffectRequireApproval,
			RuleID:     winningRule.ID,
			Layer:      winningLayer,
			Assessment: assessment,
		}, nil
	}

	if winningEffect == RuleEffectAutoApprove {
		return RuleEvaluationResult{
			Decision:   AllowPermission(),
			Effect:     RuleEffectAutoApprove,
			RuleID:     winningRule.ID,
			Layer:      winningLayer,
			Assessment: assessment,
		}, nil
	}

	return p.evaluateAutonomyMatrix(assessment), nil
}

// CheckToolPermission implements PermissionPolicy.
func (p *RulePermissionPolicy) CheckToolPermission(ctx context.Context, req *PermissionRequest) (PermissionDecision, error) {
	res, err := p.Evaluate(ctx, req)
	if err != nil {
		return PermissionDecision{}, err
	}
	return res.Decision, nil
}

func (p *RulePermissionPolicy) evaluateAutonomyMatrix(assessment SeverityAssessment) RuleEvaluationResult {
	switch p.Autonomy {
	case AutonomyReadOnly:
		if assessment.Level == SeverityRead {
			return RuleEvaluationResult{
				Decision:   AllowPermission(),
				Effect:     RuleEffectAllow,
				Assessment: assessment,
			}
		}
		return RuleEvaluationResult{
			Decision: DenyPermission(fmt.Sprintf(
				"read-only autonomy mode blocks %s action (severity=%s: %s)",
				assessment.Category, assessment.Level, strings.Join(assessment.Reasons, "; "))),
			Effect:     RuleEffectDeny,
			RuleID:     "autonomy-readonly",
			Layer:      RuleLayerOperator,
			Assessment: assessment,
		}
	case AutonomyFull:
		if assessment.Level <= SeverityMedium && !assessment.OneTimeApprovalOnly {
			return RuleEvaluationResult{
				Decision:   AllowPermission(),
				Effect:     RuleEffectAllow,
				Assessment: assessment,
			}
		}
		return RuleEvaluationResult{
			Decision: AskPermission(fmt.Sprintf(
				"approval required for %s tool call (severity=%s: %s)",
				assessment.Category, assessment.Level, strings.Join(assessment.Reasons, "; "))),
			Effect:     RuleEffectRequireApproval,
			RuleID:     "autonomy-full-high-severity",
			Layer:      RuleLayerOperator,
			Assessment: assessment,
		}
	default: // AutonomySupervised
		if assessment.Level <= SeverityLow && !assessment.OneTimeApprovalOnly {
			return RuleEvaluationResult{
				Decision:   AllowPermission(),
				Effect:     RuleEffectAllow,
				Assessment: assessment,
			}
		}
		return RuleEvaluationResult{
			Decision: AskPermission(fmt.Sprintf(
				"approval required for %s tool call (severity=%s: %s)",
				assessment.Category, assessment.Level, strings.Join(assessment.Reasons, "; "))),
			Effect:     RuleEffectRequireApproval,
			RuleID:     "autonomy-supervised-severity-gate",
			Layer:      RuleLayerOperator,
			Assessment: assessment,
		}
	}
}

func evaluateLayerNameOnly(layer RuleLayerSet, toolName string, rc RuleRuntimeContext) (RuleEffect, ToolRule) {
	var matchedEffect RuleEffect
	var matchedRule ToolRule
	for _, rule := range layer.Rules {
		if rule.Match.Category != "" || rule.Match.MinSeverity != nil {
			continue
		}
		if !ruleMatchesWhen(rule.When, rc) {
			continue
		}
		if !matchNameAndFamily(rule.Match, toolName) {
			continue
		}
		if rule.Except != nil && matchNameAndFamily(*rule.Except, toolName) {
			continue
		}
		if rule.Effect == RuleEffectDeny {
			return RuleEffectDeny, rule
		}
		if rule.Effect == RuleEffectHide && matchedEffect == "" {
			matchedEffect = RuleEffectHide
			matchedRule = rule
		}
	}
	return matchedEffect, matchedRule
}

func evaluateLayerFull(layer RuleLayerSet, toolName string, assessment SeverityAssessment, rc RuleRuntimeContext) (RuleEffect, ToolRule) {
	var bestEffect RuleEffect
	var bestRule ToolRule
	for _, rule := range layer.Rules {
		if !ruleMatchesWhen(rule.When, rc) {
			continue
		}
		if !matchRulePredicate(rule.Match, toolName, assessment) {
			continue
		}
		if rule.Except != nil && matchRulePredicate(*rule.Except, toolName, assessment) {
			continue
		}
		// Precedence inside a layer: deny > require_approval > auto_approve > hide > allow.
		switch rule.Effect {
		case RuleEffectDeny:
			return RuleEffectDeny, rule
		case RuleEffectRequireApproval:
			bestEffect = RuleEffectRequireApproval
			bestRule = rule
		case RuleEffectAutoApprove:
			if bestEffect != RuleEffectRequireApproval {
				bestEffect = RuleEffectAutoApprove
				bestRule = rule
			}
		}
	}
	return bestEffect, bestRule
}

func ruleMatchesWhen(when *ToolRuleWhen, rc RuleRuntimeContext) bool {
	if when == nil {
		return true
	}
	if when.Channel != "" && !globMatchFold(when.Channel, rc.Channel) {
		return false
	}
	if when.Agent != "" && !globMatchFold(when.Agent, rc.Agent) {
		return false
	}
	if when.Origin != "" && !globMatchFold(when.Origin, rc.Origin) {
		return false
	}
	return true
}

func matchRulePredicate(m ToolRuleMatch, toolName string, assessment SeverityAssessment) bool {
	if !matchNameAndFamily(m, toolName) {
		return false
	}
	if m.Category != "" && !strings.EqualFold(string(m.Category), string(assessment.Category)) {
		return false
	}
	if m.MinSeverity != nil && assessment.Level < *m.MinSeverity {
		return false
	}
	return true
}

func matchNameAndFamily(m ToolRuleMatch, toolName string) bool {
	if m.Name != "" && !globMatchFold(m.Name, toolName) {
		return false
	}
	if m.Family != "" {
		family := toolFamilyOf(toolName)
		if !globMatchFold(m.Family, family) {
			return false
		}
	}
	return true
}

func toolFamilyOf(toolName string) string {
	lower := strings.ToLower(strings.TrimSpace(toolName))
	if strings.HasPrefix(lower, "mcp__") {
		rest := strings.TrimPrefix(lower, "mcp__")
		if fam, _, ok := strings.Cut(rest, "__"); ok && fam != "" {
			return fam
		}
	}
	if fam, _, ok := strings.Cut(lower, "_"); ok {
		return fam
	}
	return lower
}

func globMatchFold(pattern, target string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	t := strings.ToLower(strings.TrimSpace(target))
	if p == "" {
		return true
	}
	if t == "" {
		return false
	}
	ok, err := doublestar.Match(p, t)
	return err == nil && ok
}

func formatRuleReason(rule ToolRule, layer RuleLayer, fallback string) string {
	base := strings.TrimSpace(rule.Reason)
	if base == "" {
		base = fallback
	}
	if rule.ID != "" {
		return fmt.Sprintf("[%s:%s] %s", layer, rule.ID, base)
	}
	return fmt.Sprintf("[%s] %s", layer, base)
}
