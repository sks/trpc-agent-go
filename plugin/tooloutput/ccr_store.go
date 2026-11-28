//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package tooloutput

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

const (
	// DefaultMaxEntries is the default maximum number of entries in CCRStore.
	DefaultMaxEntries = 256
	// DefaultTTL is the default time-to-live for entries in CCRStore.
	DefaultTTL = 30 * time.Minute
)

var _ OutputStore = (*CCRStore)(nil)

// CCRStore is a bounded, thread-safe, expirable in-memory OutputStore keyed by
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
	if s == nil || s.cache == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(content))
	handle := NewCCRHandle(hex.EncodeToString(sum[:]))
	s.cache.Add(handle.Hash(), content)
	return handle.String()
}

// Get retrieves content by either a ⟦ccr:<sha256>⟧ handle or a raw hex digest.
func (s *CCRStore) Get(handleOrHash string) (string, bool) {
	if s == nil || s.cache == nil {
		return "", false
	}
	handle := NewCCRHandle(handleOrHash)
	if handle.IsZero() {
		return "", false
	}
	return s.cache.Get(handle.Hash())
}

// Len returns the number of entries currently in the store.
func (s *CCRStore) Len() int {
	if s == nil || s.cache == nil {
		return 0
	}
	return s.cache.Len()
}
