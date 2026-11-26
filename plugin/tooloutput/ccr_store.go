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

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	// DefaultMaxEntries is the default maximum number of entries in CCRStore.
	DefaultMaxEntries = 256
	// DefaultTTL is the default time-to-live for entries in CCRStore.
	DefaultTTL = 30 * time.Minute

	handlePrefix = "⟦ccr:"
	handleSuffix = "⟧"
)

// CCRStore is a bounded, thread-safe, expirable in-memory store keyed by
// SHA-256 content digest.
type CCRStore struct {
	cache *expirable.LRU[string, string]
}

// NewCCRStore creates a CCRStore with the given capacity and TTL.
// Non-positive values fall back to DefaultMaxEntries and DefaultTTL.
func NewCCRStore(maxEntries int, ttl time.Duration) *CCRStore {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &CCRStore{
		cache: expirable.NewLRU[string, string](maxEntries, nil, ttl),
	}
}

// Put stores content under its SHA-256 digest and returns a ⟦ccr:<sha256>⟧ handle.
func (s *CCRStore) Put(content string) string {
	sum := sha256.Sum256([]byte(content))
	hash := hex.EncodeToString(sum[:])
	s.cache.Add(hash, content)
	return FormatHandle(hash)
}

// Get retrieves content by either a ⟦ccr:<sha256>⟧ handle or a raw hex digest.
func (s *CCRStore) Get(handleOrHash string) (string, bool) {
	if s == nil {
		return "", false
	}
	hash := ParseHandle(handleOrHash)
	if hash == "" {
		return "", false
	}
	return s.cache.Get(hash)
}

// Len returns the number of entries currently in the store.
func (s *CCRStore) Len() int {
	if s == nil {
		return 0
	}
	return s.cache.Len()
}

// FormatHandle wraps a SHA-256 hex digest in ⟦ccr:...⟧ delimiters.
func FormatHandle(hash string) string {
	return handlePrefix + hash + handleSuffix
}

// ParseHandle extracts the SHA-256 hex digest from a ⟦ccr:...⟧ handle,
// or returns the trimmed input if it is already a raw digest.
func ParseHandle(ref string) string {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, handlePrefix) && strings.HasSuffix(ref, handleSuffix) {
		return strings.TrimSuffix(strings.TrimPrefix(ref, handlePrefix), handleSuffix)
	}
	return ref
}
