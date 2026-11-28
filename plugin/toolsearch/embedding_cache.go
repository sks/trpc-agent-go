//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
// trpc-agent-go is licensed under the Apache License Version 2.0.
//
//

package toolsearch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"

	"trpc.group/trpc-go/trpc-agent-go/tool"
)

// EmbeddingStore is the port interface for content-addressed embedding persistence.
type EmbeddingStore interface {
	Get(hash string) ([]float64, bool)
	Put(hash string, vec []float64)
	Len() int
}

// DeclarationHasher computes deterministic SHA-256 content hashes over tool
// names, descriptions, and input JSON schemas so unchanged tools skip re-embedding.
type DeclarationHasher struct{}

// NewDeclarationHasher returns a DeclarationHasher.
func NewDeclarationHasher() DeclarationHasher {
	return DeclarationHasher{}
}

// ComputeToolContentHash computes a deterministic SHA-256 content hash over t's declaration.
func (DeclarationHasher) ComputeToolContentHash(t tool.Tool) string {
	if t == nil {
		return ""
	}
	return (DeclarationHasher{}).ComputeDeclarationContentHash(t.Declaration())
}

// ComputeDeclarationContentHash computes a deterministic SHA-256 content hash over:
//
//	decl.Name + "\x00" + decl.Description + "\x00" + schema_json
func (DeclarationHasher) ComputeDeclarationContentHash(decl *tool.Declaration) string {
	if decl == nil {
		return ""
	}
	var schemaJSON string
	if decl.InputSchema != nil {
		data, err := json.Marshal(decl.InputSchema)
		if err == nil {
			schemaJSON = string(data)
		}
	}
	payload := decl.Name + "\x00" + decl.Description + "\x00" + schemaJSON
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// ComputeToolContentHash computes a deterministic SHA-256 content hash over:
//
//	name + "\x00" + description + "\x00" + schema_json
//
// Repeated indexing / startup uses this digest to skip re-embedding tools whose
// name, description, and input schema have not changed.
func ComputeToolContentHash(t tool.Tool) string {
	return DeclarationHasher{}.ComputeToolContentHash(t)
}

// ComputeDeclarationContentHash computes a deterministic SHA-256 content hash
// over decl.Name + "\x00" + decl.Description + "\x00" + schema_json.
func ComputeDeclarationContentHash(decl *tool.Declaration) string {
	return DeclarationHasher{}.ComputeDeclarationContentHash(decl)
}

var _ EmbeddingStore = (*EmbeddingCache)(nil)

// EmbeddingCache is a thread-safe, additive content-hash EmbeddingStore that
// maps a tool's SHA-256 content hash (and tool name) to its previously computed
// embedding vector. When a tool's content hash is unchanged across indexing
// passes or restarts, its cached vector is reused without invoking the remote embedder.
type EmbeddingCache struct {
	mu         sync.RWMutex
	byHash     map[string][]float64
	hashByTool map[string]string
	hits       int64
	misses     int64
}

// NewEmbeddingCache creates an empty EmbeddingCache.
func NewEmbeddingCache() *EmbeddingCache {
	return &EmbeddingCache{
		byHash:     make(map[string][]float64),
		hashByTool: make(map[string]string),
	}
}

// Get implements EmbeddingStore by looking up contentHash and tracking hit/miss statistics.
func (c *EmbeddingCache) Get(hash string) ([]float64, bool) {
	return c.Lookup(hash)
}

// Put implements EmbeddingStore by storing vec under hash.
func (c *EmbeddingCache) Put(hash string, vec []float64) {
	c.Store("", hash, vec)
}

// Len implements EmbeddingStore by returning the number of unique content hashes cached.
func (c *EmbeddingCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.byHash)
}

// Lookup returns a defensive copy of the cached embedding for contentHash if present.
func (c *EmbeddingCache) Lookup(contentHash string) ([]float64, bool) {
	if c == nil || contentHash == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	vec, ok := c.byHash[contentHash]
	if !ok {
		c.misses++
		return nil, false
	}
	c.hits++
	cp := make([]float64, len(vec))
	copy(cp, vec)
	return cp, true
}

// Store records an embedding for toolName and contentHash.
func (c *EmbeddingCache) Store(toolName, contentHash string, vec []float64) {
	if c == nil || contentHash == "" || len(vec) == 0 {
		return
	}
	cp := make([]float64, len(vec))
	copy(cp, vec)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byHash[contentHash] = cp
	if toolName != "" {
		c.hashByTool[toolName] = contentHash
	}
}

// IsUnchanged reports whether toolName is already cached with contentHash.
func (c *EmbeddingCache) IsUnchanged(toolName, contentHash string) bool {
	if c == nil || toolName == "" || contentHash == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	prev, ok := c.hashByTool[toolName]
	if !ok || prev != contentHash {
		return false
	}
	_, hasVec := c.byHash[contentHash]
	return hasVec
}

// Invalidate removes toolName's association from the cache. The underlying
// content-hash vector remains available if the exact declaration reappears.
func (c *EmbeddingCache) Invalidate(toolName string) {
	if c == nil || toolName == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.hashByTool, toolName)
}

// Stats returns the cumulative cache hits, misses, and number of unique hashes stored.
func (c *EmbeddingCache) Stats() (hits, misses int64, entries int) {
	if c == nil {
		return 0, 0, 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, len(c.byHash)
}
