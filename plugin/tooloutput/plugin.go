//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package tooloutput

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	pluginbase "trpc.group/trpc-go/trpc-agent-go/plugin"
	"trpc.group/trpc-go/trpc-agent-go/tool"
)

const (
	// DefaultPluginName is the default name of the tooloutput plugin.
	DefaultPluginName = "tooloutput"
	// DefaultThreshold is the character length above which tool output is compacted.
	DefaultThreshold = 10000
	// DefaultMaxChars is the target character budget for compacted output.
	DefaultMaxChars = 6000
	// FocusArgKey is the optional tool argument key stripped in BeforeTool.
	FocusArgKey = "result_focus"
)

// Option configures the tooloutput plugin.
type Option func(*options)

type options struct {
	name           string
	outputStore    OutputStore
	ccrStore       *CCRStore
	shaperRegistry *ShaperRegistry
	threshold      int
	maxChars       int
	maxEntries     int
	ttl            time.Duration
}

// WithName sets the plugin name.
func WithName(name string) Option {
	return func(o *options) {
		if name != "" {
			o.name = name
		}
	}
}

// WithStore sets a custom CCRStore.
func WithStore(store *CCRStore) Option {
	return func(o *options) {
		if store != nil {
			o.ccrStore = store
			o.outputStore = store
		}
	}
}

// WithOutputStore sets a custom OutputStore implementation.
func WithOutputStore(store OutputStore) Option {
	return func(o *options) {
		if store != nil {
			o.outputStore = store
			if ccr, ok := store.(*CCRStore); ok {
				o.ccrStore = ccr
			} else {
				o.ccrStore = nil
			}
		}
	}
}

// WithShaperRegistry sets a custom ShaperRegistry for deterministic output shaping.
func WithShaperRegistry(registry *ShaperRegistry) Option {
	return func(o *options) {
		if registry != nil {
			o.shaperRegistry = registry
		}
	}
}

// WithThreshold sets the character threshold above which outputs are compacted.
func WithThreshold(threshold int) Option {
	return func(o *options) {
		if threshold > 0 {
			o.threshold = threshold
		}
	}
}

// WithMaxChars sets the target character budget for compacted outputs.
func WithMaxChars(maxChars int) Option {
	return func(o *options) {
		if maxChars > 0 {
			o.maxChars = maxChars
		}
	}
}

// WithMaxEntries sets the CCRStore capacity when no custom store is provided.
func WithMaxEntries(maxEntries int) Option {
	return func(o *options) {
		if maxEntries > 0 {
			o.maxEntries = maxEntries
		}
	}
}

// WithTTL sets the CCRStore TTL when no custom store is provided.
func WithTTL(ttl time.Duration) Option {
	return func(o *options) {
		if ttl > 0 {
			o.ttl = ttl
		}
	}
}

// Plugin is the tooloutput compaction plugin.
type Plugin struct {
	name        string
	outputStore OutputStore
	ccrStore    *CCRStore
	shapers     *ShaperRegistry
	threshold   int
	maxChars    int
	focusMu     sync.Mutex
	focusByID   map[string]string
}

// New creates a new tooloutput compaction plugin.
func New(opts ...Option) *Plugin {
	o := options{
		name:       DefaultPluginName,
		threshold:  DefaultThreshold,
		maxChars:   DefaultMaxChars,
		maxEntries: DefaultMaxEntries,
		ttl:        DefaultTTL,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	outputStore := o.outputStore
	ccrStore := o.ccrStore
	if outputStore == nil {
		ccrStore = NewCCRStore(o.maxEntries, o.ttl)
		outputStore = ccrStore
	}
	shapers := o.shaperRegistry
	if shapers == nil {
		shapers = NewDefaultShaperRegistry()
	}
	return &Plugin{
		name:        o.name,
		outputStore: outputStore,
		ccrStore:    ccrStore,
		shapers:     shapers,
		threshold:   o.threshold,
		maxChars:    o.maxChars,
		focusByID:   make(map[string]string),
	}
}

// Name implements plugin.Plugin.
func (p *Plugin) Name() string {
	if p == nil {
		return ""
	}
	return p.name
}

// Store returns the underlying CCRStore when backed by a CCRStore, or nil if a
// custom non-CCR OutputStore was configured via WithOutputStore.
func (p *Plugin) Store() *CCRStore {
	if p == nil {
		return nil
	}
	return p.ccrStore
}

// OutputStore returns the OutputStore port configured on this plugin.
func (p *Plugin) OutputStore() OutputStore {
	if p == nil {
		return nil
	}
	return p.outputStore
}

// ShaperRegistry returns the ShaperRegistry configured on this plugin.
func (p *Plugin) ShaperRegistry() *ShaperRegistry {
	if p == nil {
		return nil
	}
	return p.shapers
}

// Tools returns the zero-LLM CCR inspection tools bound to this plugin's store.
func (p *Plugin) Tools() []tool.Tool {
	if p == nil {
		return nil
	}
	return NewTools(p.outputStore)
}

// Register implements plugin.Plugin.
func (p *Plugin) Register(r *pluginbase.Registry) {
	if p == nil || r == nil {
		return
	}
	r.BeforeTool(p.beforeTool)
	r.AfterTool(p.afterTool)
}

func (p *Plugin) beforeTool(_ context.Context, args *tool.BeforeToolArgs) (*tool.BeforeToolResult, error) {
	if p == nil || args == nil || len(args.Arguments) == 0 {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(args.Arguments, &m); err != nil {
		return nil, nil
	}
	rawFocus, ok := m[FocusArgKey]
	if !ok {
		return nil, nil
	}
	delete(m, FocusArgKey)
	modified, err := json.Marshal(m)
	if err != nil {
		return nil, nil
	}
	if focus, ok := rawFocus.(string); ok && focus != "" && args.ToolCallID != "" {
		p.focusMu.Lock()
		p.focusByID[args.ToolCallID] = focus
		p.focusMu.Unlock()
	}
	return &tool.BeforeToolResult{
		ModifiedArguments: modified,
	}, nil
}

func (p *Plugin) afterTool(_ context.Context, args *tool.AfterToolArgs) (*tool.AfterToolResult, error) {
	if p == nil || args == nil || args.Error != nil || args.Result == nil {
		return nil, nil
	}
	if args.ToolName == "tool_result_retrieve" || args.ToolName == "tool_result_query" {
		return nil, nil
	}

	focus := ""
	if args.ToolCallID != "" {
		p.focusMu.Lock()
		focus = p.focusByID[args.ToolCallID]
		delete(p.focusByID, args.ToolCallID)
		p.focusMu.Unlock()
	}

	raw := serializeResult(args.Result)
	if len(raw) <= p.threshold && focus == "" {
		return nil, nil
	}

	shapers := p.shapers
	if shapers == nil {
		shapers = defaultShaperRegistry
	}
	res := shapers.ShapeResult(raw, p.maxChars, focus)
	if !res.Changed {
		return nil, nil
	}
	handle := p.outputStore.Put(raw)
	compacted := fmt.Sprintf("%s\n\n[Full output stored in CCR: %s (%d chars). Use tool_result_retrieve or tool_result_query to inspect.]", res.Content, handle, len(raw))
	return &tool.AfterToolResult{
		CustomResult: compacted,
	}, nil
}

func serializeResult(res any) string {
	switch v := res.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	}
}
