//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

// Package engram implements ENGRAM-style typed memory: episodic, semantic, and procedural.
// See docs/memory_paradigms_integration_map.md and ENGRAM (arxiv 2511.12960) for context.
//
// ENGRAM reuses memory.UserKey (AppName, UserID) and memory's key-validation errors from
// trpc-agent-go/memory so that one key type and error contract apply across memory features.
package engram

import (
	"errors"
	"strings"
	"time"

	"trpc.group/trpc-go/trpc-agent-go/memory"
)

var (
	// ErrAppNameRequired and ErrUserIDRequired match memory package for consistent validation.
	ErrAppNameRequired = memory.ErrAppNameRequired
	ErrUserIDRequired  = memory.ErrUserIDRequired
	// ErrRecordContentRequired is returned when record content is empty.
	ErrRecordContentRequired = errors.New("engram: record content is required")
	// ErrInvalidMemoryType is returned when memory type is not one of the allowed values.
	ErrInvalidMemoryType = errors.New("engram: invalid memory type")
)

// UserKey is the same as memory.UserKey: app and user scope for ENGRAM records.
// Use CheckUserKey() for validation. This alias keeps ENGRAM API clear while sharing the key type.
type UserKey = memory.UserKey

// MemoryType is the ENGRAM memory type: episodic (events), semantic (facts/preferences), or procedural (routines).
type MemoryType string

const (
	// TypeEpisodic is time-sequenced events (what happened, when).
	TypeEpisodic MemoryType = "episodic"
	// TypeSemantic is stable facts and user preferences.
	TypeSemantic MemoryType = "semantic"
	// TypeProcedural is task-specific routines and instructions.
	TypeProcedural MemoryType = "procedural"
)

// Valid returns true if t is one of the three ENGRAM types.
func (t MemoryType) Valid() bool {
	switch t {
	case TypeEpisodic, TypeSemantic, TypeProcedural:
		return true
	default:
		return false
	}
}

// String returns the lowercase string form of the memory type.
func (t MemoryType) String() string { return string(t) }

// ParseMemoryType parses a string into MemoryType. Empty or unknown returns TypeEpisodic and false.
func ParseMemoryType(s string) (MemoryType, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "episodic":
		return TypeEpisodic, true
	case "semantic":
		return TypeSemantic, true
	case "procedural":
		return TypeProcedural, true
	default:
		return TypeEpisodic, false
	}
}

// Record is a single ENGRAM memory record with type, content, and optional metadata.
type Record struct {
	ID        string     `json:"id"`
	AppName   string     `json:"app_name"`
	UserID    string     `json:"user_id"`
	Type      MemoryType `json:"type"`
	Content   string     `json:"content"`
	Title     string     `json:"title,omitempty"`     // optional short title (e.g. for episodic)
	Topics    []string   `json:"topics,omitempty"`   // optional topics for retrieval
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// RetrieveOptions configures retrieval (top-k per type, optional query filter).
type RetrieveOptions struct {
	// TopKPerType is the maximum number of records to return per memory type. Default 3.
	TopKPerType int
	// Query is an optional query string for filtering/ranking (implementations may use keyword match or embedding).
	Query string
	// Types limits retrieval to these types only. Empty means all three types.
	Types []MemoryType
}

// DefaultRetrieveOptions returns sensible defaults for retrieval.
func DefaultRetrieveOptions() RetrieveOptions {
	return RetrieveOptions{
		TopKPerType: 3,
		Types:       []MemoryType{TypeEpisodic, TypeSemantic, TypeProcedural},
	}
}
