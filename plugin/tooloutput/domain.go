//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

// Package tooloutput provides deterministic tool output compaction with a
// bounded Content-Cache-Retrieve (CCR) store and zero-LLM inspection tools.
package tooloutput

import "strings"

const (
	handlePrefix = "⟦ccr:"
	handleSuffix = "⟧"
)

// ContentType identifies the detected structure of a tool output.
type ContentType string

const (
	// ContentJSON identifies valid JSON object or array payloads.
	ContentJSON ContentType = "json"
	// ContentDiff identifies unified git diff payloads.
	ContentDiff ContentType = "diff"
	// ContentSearch identifies file:line search/grep match listings.
	ContentSearch ContentType = "search"
	// ContentCode identifies source-code files or snippets.
	ContentCode ContentType = "code"
	// ContentLog identifies unstructured text or log streams.
	ContentLog ContentType = "log"
)

// CCRHandle is an immutable value object representing a Content-Cache-Retrieve
// reference (`⟦ccr:<sha256>⟧`).
type CCRHandle struct {
	hash string
}

// NewCCRHandle constructs a CCRHandle from either a ⟦ccr:...⟧ token or a raw digest.
func NewCCRHandle(handleOrHash string) CCRHandle {
	return CCRHandle{hash: ParseHandle(handleOrHash)}
}

// Hash returns the normalized digest without handle delimiters.
func (h CCRHandle) Hash() string {
	return h.hash
}

// IsZero reports whether the handle is empty.
func (h CCRHandle) IsZero() bool {
	return h.hash == ""
}

// String renders the delimited ⟦ccr:<hash>⟧ token, or "" when empty.
func (h CCRHandle) String() string {
	if h.hash == "" {
		return ""
	}
	return FormatHandle(h.hash)
}

// FormatHandle wraps a SHA-256 hex digest in ⟦ccr:...⟧ delimiters.
func FormatHandle(hash string) string {
	hash = ParseHandle(hash)
	if hash == "" {
		return ""
	}
	return handlePrefix + hash + handleSuffix
}

// ParseHandle extracts the SHA-256 hex digest from a ⟦ccr:...⟧ handle,
// or returns the trimmed input if it is already a raw digest.
func ParseHandle(ref string) string {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, handlePrefix) && strings.HasSuffix(ref, handleSuffix) {
		return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(ref, handlePrefix), handleSuffix))
	}
	return ref
}

// ShapeResult captures the outcome of shaping a tool output payload.
type ShapeResult struct {
	Content     string
	ContentType ContentType
	Changed     bool
}

// OutputStore is the port interface for storing and retrieving full tool outputs
// keyed by content digest.
type OutputStore interface {
	Put(content string) string
	Get(handleOrHash string) (string, bool)
	Len() int
}

// ContentShaper compacts a specific class of tool output within a character budget.
type ContentShaper interface {
	ContentType() ContentType
	CanShape(text string) bool
	Shape(text string, maxChars int, focus string) string
}
