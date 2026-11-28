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

// RuleAction specifies the policy action of a matching PermissionRule.
type RuleAction string

// RuleEffect is an alias for RuleAction for backward compatibility.
type RuleEffect = RuleAction

const (
	// RuleActionAllow permits the tool to be advertised, searched, and executed (subject to severity tier).
	RuleActionAllow RuleAction = "allow"
	// RuleActionDeny blocks the tool across wire schemas, tool_search, and execution.
	RuleActionDeny RuleAction = "deny"
	// RuleActionHide omits the tool from initial wire schemas while keeping it callable (e.g. via call_tool).
	RuleActionHide RuleAction = "hide"
	// RuleActionRequireApproval forces a permission ask before execution regardless of autonomy tier.
	RuleActionRequireApproval RuleAction = "require_approval"
	// RuleActionAutoApprove waives approval prompts for matching non-critical tool calls.
	RuleActionAutoApprove RuleAction = "auto_approve"

	// Backward-compatible RuleEffect constant aliases.
	RuleEffectAllow           = RuleActionAllow
	RuleEffectDeny            = RuleActionDeny
	RuleEffectHide            = RuleActionHide
	RuleEffectRequireApproval = RuleActionRequireApproval
	RuleEffectAutoApprove     = RuleActionAutoApprove
)

// AutonomyMode configures the baseline severity gate for a session or agent.
type AutonomyMode string

// AutonomyLevel is an alias for AutonomyMode for backward compatibility.
type AutonomyLevel = AutonomyMode

const (
	// AutonomyReadOnly allows SeverityRead and denies all mutating calls (SeverityLow..Critical).
	AutonomyReadOnly AutonomyMode = "readonly"
	// AutonomySupervised auto-approves SeverityRead and SeverityLow, prompts for Medium/High, and forces one-time prompt for Critical.
	AutonomySupervised AutonomyMode = "supervised"
	// AutonomyFull auto-approves SeverityRead..Medium, prompts for High/Critical.
	AutonomyFull AutonomyMode = "full"
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

// ToolRuleMatch defines glob and severity match predicates for a PermissionRule.
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

// MatchesNameAndFamily reports whether toolName satisfies the Name and Family predicates.
func (m ToolRuleMatch) MatchesNameAndFamily(toolName string) bool {
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

// Matches reports whether toolName and assessment satisfy all predicates on m.
func (m ToolRuleMatch) Matches(toolName string, assessment SeverityAssessment) bool {
	if !m.MatchesNameAndFamily(toolName) {
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

// ToolRuleWhen restricts a rule to a specific runtime context.
type ToolRuleWhen struct {
	// Channel matches the active messaging channel (e.g. "slack", "telegram", "web").
	Channel string `json:"channel,omitempty" yaml:"channel,omitempty" toml:"channel,omitempty"`
	// Agent matches the active agent name or archetype.
	Agent string `json:"agent,omitempty" yaml:"agent,omitempty" toml:"agent,omitempty"`
	// Origin matches the turn origin (e.g. "interactive_user", "local_schedule", "external_trigger").
	Origin string `json:"origin,omitempty" yaml:"origin,omitempty" toml:"origin,omitempty"`
}

// Matches reports whether rc satisfies the contextual constraints in w.
func (w *ToolRuleWhen) Matches(rc RuleRuntimeContext) bool {
	if w == nil {
		return true
	}
	if w.Channel != "" && !globMatchFold(w.Channel, rc.Channel) {
		return false
	}
	if w.Agent != "" && !globMatchFold(w.Agent, rc.Agent) {
		return false
	}
	if w.Origin != "" && !globMatchFold(w.Origin, rc.Origin) {
		return false
	}
	return true
}

// PermissionRule is one declarative tool governance rule.
type PermissionRule struct {
	ID     string         `json:"id,omitempty" yaml:"id,omitempty" toml:"id,omitempty"`
	Effect RuleAction     `json:"effect" yaml:"effect" toml:"effect"`
	Match  ToolRuleMatch  `json:"match" yaml:"match" toml:"match"`
	Except *ToolRuleMatch `json:"except,omitempty" yaml:"except,omitempty" toml:"except,omitempty"`
	When   *ToolRuleWhen  `json:"when,omitempty" yaml:"when,omitempty" toml:"when,omitempty"`
	Reason string         `json:"reason,omitempty" yaml:"reason,omitempty" toml:"reason,omitempty"`
}

// ToolRule is an alias for PermissionRule for backward compatibility.
type ToolRule = PermissionRule

// MatchesNameOnly reports whether r matches toolName and rc without runtime severity predicates.
func (r PermissionRule) MatchesNameOnly(toolName string, rc RuleRuntimeContext) bool {
	if r.Match.Category != "" || r.Match.MinSeverity != nil {
		return false
	}
	if !r.When.Matches(rc) {
		return false
	}
	if !r.Match.MatchesNameAndFamily(toolName) {
		return false
	}
	if r.Except != nil && r.Except.MatchesNameAndFamily(toolName) {
		return false
	}
	return true
}

// MatchesFull reports whether r matches toolName, assessment, and rc.
func (r PermissionRule) MatchesFull(toolName string, assessment SeverityAssessment, rc RuleRuntimeContext) bool {
	if !r.When.Matches(rc) {
		return false
	}
	if !r.Match.Matches(toolName, assessment) {
		return false
	}
	if r.Except != nil && r.Except.Matches(toolName, assessment) {
		return false
	}
	return true
}

// FormatReason formats a structured human-readable explanation tagged with layer and rule ID.
func (r PermissionRule) FormatReason(layer RuleLayer, fallback string) string {
	base := strings.TrimSpace(r.Reason)
	if base == "" {
		base = fallback
	}
	if r.ID != "" {
		return fmt.Sprintf("[%s:%s] %s", layer, r.ID, base)
	}
	return fmt.Sprintf("[%s] %s", layer, base)
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

// PermissionRuleSet holds the rules belonging to one RuleLayer.
type PermissionRuleSet struct {
	Layer RuleLayer
	Rules []PermissionRule
}

// RuleLayerSet is an alias for PermissionRuleSet for backward compatibility.
type RuleLayerSet = PermissionRuleSet

// EvaluateNameOnly evaluates static wire/search visibility rules in s.
func (s PermissionRuleSet) EvaluateNameOnly(toolName string, rc RuleRuntimeContext) (RuleAction, PermissionRule) {
	var matchedEffect RuleAction
	var matchedRule PermissionRule
	for _, rule := range s.Rules {
		if !rule.MatchesNameOnly(toolName, rc) {
			continue
		}
		if rule.Effect == RuleActionDeny {
			return RuleActionDeny, rule
		}
		if rule.Effect == RuleActionHide && matchedEffect == "" {
			matchedEffect = RuleActionHide
			matchedRule = rule
		}
	}
	return matchedEffect, matchedRule
}

// Evaluate evaluates runtime execution rules in s with precedence:
// deny > require_approval > auto_approve > hide > allow.
func (s PermissionRuleSet) Evaluate(toolName string, assessment SeverityAssessment, rc RuleRuntimeContext) (RuleAction, PermissionRule) {
	var bestEffect RuleAction
	var bestRule PermissionRule
	for _, rule := range s.Rules {
		if !rule.MatchesFull(toolName, assessment, rc) {
			continue
		}
		switch rule.Effect {
		case RuleActionDeny:
			return RuleActionDeny, rule
		case RuleActionRequireApproval:
			bestEffect = RuleActionRequireApproval
			bestRule = rule
		case RuleActionAutoApprove:
			if bestEffect != RuleActionRequireApproval {
				bestEffect = RuleActionAutoApprove
				bestRule = rule
			}
		}
	}
	return bestEffect, bestRule
}

// RuleEvaluationInput encapsulates the request and runtime scope evaluated by a RuleEvaluator.
type RuleEvaluationInput struct {
	Request        *PermissionRequest
	RuntimeContext RuleRuntimeContext
}

// NewRuleEvaluationInput constructs a RuleEvaluationInput from ctx and req.
func NewRuleEvaluationInput(ctx context.Context, req *PermissionRequest) RuleEvaluationInput {
	return RuleEvaluationInput{
		Request:        req,
		RuntimeContext: RuleRuntimeContextFrom(ctx),
	}
}

// RuleDecision describes the outcome of evaluating the 3-layer rule stack and severity gate.
type RuleDecision struct {
	Decision   PermissionDecision
	Effect     RuleAction
	RuleID     string
	Layer      RuleLayer
	Assessment SeverityAssessment
}

// RuleEvaluationResult is an alias for RuleDecision for backward compatibility.
type RuleEvaluationResult = RuleDecision

// RuleEvaluator evaluates layered permission rules, wire visibility, and searchability.
type RuleEvaluator interface {
	Evaluate(ctx context.Context, req *PermissionRequest) (RuleDecision, error)
	EvaluateInput(ctx context.Context, input RuleEvaluationInput) (RuleDecision, error)
	IsVisibleOnWire(ctx context.Context, toolName string) bool
	IsSearchable(ctx context.Context, toolName string) bool
}

var (
	_ PermissionPolicy = (*RulePermissionPolicy)(nil)
	_ RuleEvaluator    = (*RulePermissionPolicy)(nil)
)

// RulePermissionPolicy evaluates 3-layer declarative tool rules plus severity-based autonomy gating.
type RulePermissionPolicy struct {
	Autonomy   AutonomyMode
	Classifier SeverityClassifier
	Layers     []PermissionRuleSet
}

// NewRulePermissionPolicy creates a RulePermissionPolicy for the given autonomy tier, classifier, and rule layers.
func NewRulePermissionPolicy(autonomy AutonomyMode, classifier SeverityClassifier, layers ...PermissionRuleSet) *RulePermissionPolicy {
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

// ForSubAgent projects a child RulePermissionPolicy that retains the Operator layer
// and replaces the Archetype layer with the sub-agent's own rule layer.
func (p *RulePermissionPolicy) ForSubAgent(subAgentRules []PermissionRule) *RulePermissionPolicy {
	if p == nil {
		return NewRulePermissionPolicy(AutonomySupervised, nil, PermissionRuleSet{
			Layer: RuleLayerSubAgent,
			Rules: subAgentRules,
		})
	}
	var nextLayers []PermissionRuleSet
	for _, layer := range p.Layers {
		if layer.Layer == RuleLayerOperator {
			nextLayers = append(nextLayers, layer)
		}
	}
	if len(subAgentRules) > 0 {
		nextLayers = append(nextLayers, PermissionRuleSet{
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
		effect, _ := layer.EvaluateNameOnly(toolName, rc)
		if effect == RuleActionDeny || effect == RuleActionHide {
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
		effect, _ := layer.EvaluateNameOnly(toolName, rc)
		if effect == RuleActionDeny {
			return false
		}
	}
	return true
}

// Evaluate runs full rule + severity evaluation for req using the runtime context in ctx.
func (p *RulePermissionPolicy) Evaluate(ctx context.Context, req *PermissionRequest) (RuleDecision, error) {
	return p.EvaluateInput(ctx, NewRuleEvaluationInput(ctx, req))
}

// EvaluateInput runs full rule + severity evaluation for an explicit RuleEvaluationInput.
func (p *RulePermissionPolicy) EvaluateInput(ctx context.Context, input RuleEvaluationInput) (RuleDecision, error) {
	if p == nil || input.Request == nil {
		return RuleDecision{
			Decision: AllowPermission(),
			Effect:   RuleActionAllow,
		}, nil
	}

	req := input.Request
	rc := input.RuntimeContext
	if rc == (RuleRuntimeContext{}) {
		rc = RuleRuntimeContextFrom(ctx)
	}

	classifier := p.Classifier
	if classifier == nil {
		classifier = NewDefaultSeverityClassifier("")
	}
	assessment, err := classifier.ClassifyToolCall(ctx, req)
	if err != nil {
		return RuleDecision{}, err
	}

	// Escalate severity for untrusted external triggers.
	if strings.EqualFold(rc.Origin, "external_trigger") && assessment.Level > SeverityRead && assessment.Level < SeverityCritical {
		assessment.Level++
		assessment.Reasons = append(assessment.Reasons, "severity escalated +1 tier for external_trigger origin")
	}

	// Protected-path floor cannot be overridden by auto_approve rules.
	if assessment.ProtectedPathHit {
		reason := fmt.Sprintf("[operator:protected-path-floor] blocked by protected-path floor (%s)", strings.Join(assessment.Reasons, "; "))
		return RuleDecision{
			Decision:   DenyPermission(reason),
			Effect:     RuleActionDeny,
			RuleID:     "protected-path-floor",
			Layer:      RuleLayerOperator,
			Assessment: assessment,
		}, nil
	}

	var winningEffect RuleAction
	var winningRule PermissionRule
	var winningLayer RuleLayer

	for _, layer := range p.Layers {
		effect, rule := layer.Evaluate(req.ToolName, assessment, rc)
		if effect == RuleActionDeny {
			reason := rule.FormatReason(layer.Layer, "denied by tool rule")
			return RuleDecision{
				Decision:   DenyPermission(reason),
				Effect:     RuleActionDeny,
				RuleID:     rule.ID,
				Layer:      layer.Layer,
				Assessment: assessment,
			}, nil
		}
		if effect == RuleActionRequireApproval {
			winningEffect = RuleActionRequireApproval
			winningRule = rule
			winningLayer = layer.Layer
		}
		if effect == RuleActionAutoApprove && winningEffect != RuleActionRequireApproval && !assessment.OneTimeApprovalOnly {
			winningEffect = RuleActionAutoApprove
			winningRule = rule
			winningLayer = layer.Layer
		}
	}

	if winningEffect == RuleActionRequireApproval {
		reason := winningRule.FormatReason(winningLayer,
			fmt.Sprintf("approval required by rule (severity=%s)", assessment.Level))
		return RuleDecision{
			Decision:   AskPermission(reason),
			Effect:     RuleActionRequireApproval,
			RuleID:     winningRule.ID,
			Layer:      winningLayer,
			Assessment: assessment,
		}, nil
	}

	if winningEffect == RuleActionAutoApprove {
		return RuleDecision{
			Decision:   AllowPermission(),
			Effect:     RuleActionAutoApprove,
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

func (p *RulePermissionPolicy) evaluateAutonomyMatrix(assessment SeverityAssessment) RuleDecision {
	switch p.Autonomy {
	case AutonomyReadOnly:
		if assessment.Level == SeverityRead {
			return RuleDecision{
				Decision:   AllowPermission(),
				Effect:     RuleActionAllow,
				Assessment: assessment,
			}
		}
		return RuleDecision{
			Decision: DenyPermission(fmt.Sprintf(
				"read-only autonomy mode blocks %s action (severity=%s: %s)",
				assessment.Category, assessment.Level, strings.Join(assessment.Reasons, "; "))),
			Effect:     RuleActionDeny,
			RuleID:     "autonomy-readonly",
			Layer:      RuleLayerOperator,
			Assessment: assessment,
		}
	case AutonomyFull:
		if assessment.Level <= SeverityMedium && !assessment.OneTimeApprovalOnly {
			return RuleDecision{
				Decision:   AllowPermission(),
				Effect:     RuleActionAllow,
				Assessment: assessment,
			}
		}
		return RuleDecision{
			Decision: AskPermission(fmt.Sprintf(
				"approval required for %s tool call (severity=%s: %s)",
				assessment.Category, assessment.Level, strings.Join(assessment.Reasons, "; "))),
			Effect:     RuleActionRequireApproval,
			RuleID:     "autonomy-full-high-severity",
			Layer:      RuleLayerOperator,
			Assessment: assessment,
		}
	default: // AutonomySupervised
		if assessment.Level <= SeverityLow && !assessment.OneTimeApprovalOnly {
			return RuleDecision{
				Decision:   AllowPermission(),
				Effect:     RuleActionAllow,
				Assessment: assessment,
			}
		}
		return RuleDecision{
			Decision: AskPermission(fmt.Sprintf(
				"approval required for %s tool call (severity=%s: %s)",
				assessment.Category, assessment.Level, strings.Join(assessment.Reasons, "; "))),
			Effect:     RuleActionRequireApproval,
			RuleID:     "autonomy-supervised-severity-gate",
			Layer:      RuleLayerOperator,
			Assessment: assessment,
		}
	}
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
