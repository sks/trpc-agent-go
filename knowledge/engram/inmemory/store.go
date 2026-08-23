//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

// Package inmemory provides an in-memory implementation of engram.Store.
package inmemory

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"trpc.group/trpc-go/trpc-agent-go/knowledge/engram"
)

var _ engram.Store = (*Store)(nil)

type userBucket struct {
	mu      sync.RWMutex
	records []*engram.Record // all records for this user, any type
}

// Store is an in-memory ENGRAM store. Records are kept per (AppName, UserID).
type Store struct {
	mu    sync.RWMutex
	users map[string]map[string]*userBucket // appName -> userID -> bucket
}

// New returns a new in-memory ENGRAM store.
func New() *Store {
	return &Store{
		users: make(map[string]map[string]*userBucket),
	}
}

func (s *Store) getBucket(key engram.UserKey) *userBucket {
	s.mu.RLock()
	app, ok := s.users[key.AppName]
	if ok {
		b, ok := app[key.UserID]
		if ok {
			s.mu.RUnlock()
			return b
		}
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.users[key.AppName] == nil {
		s.users[key.AppName] = make(map[string]*userBucket)
	}
	if s.users[key.AppName][key.UserID] == nil {
		s.users[key.AppName][key.UserID] = &userBucket{
			records: make([]*engram.Record, 0),
		}
	}
	return s.users[key.AppName][key.UserID]
}

func generateID(key engram.UserKey, typ engram.MemoryType, content string) string {
	h := sha256.Sum256([]byte(key.AppName + "|" + key.UserID + "|" + string(typ) + "|" + content))
	return fmt.Sprintf("%x", h[:8])
}

// Add adds a typed record. If Record.ID is empty, an ID is generated. CreatedAt/UpdatedAt are set if zero.
func (s *Store) Add(ctx context.Context, key engram.UserKey, record engram.Record) (*engram.Record, error) {
	if err := key.CheckUserKey(); err != nil {
		return nil, err
	}
	if record.Content == "" {
		return nil, engram.ErrRecordContentRequired
	}
	if !record.Type.Valid() {
		return nil, engram.ErrInvalidMemoryType
	}

	now := time.Now()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	record.AppName = key.AppName
	record.UserID = key.UserID
	if record.ID == "" {
		record.ID = uuid.New().String()
	}

	// Copy so caller cannot mutate
	out := &record

	b := s.getBucket(key)
	b.mu.Lock()
	defer b.mu.Unlock()

	// Replace existing by ID if present
	for i, r := range b.records {
		if r.ID == out.ID {
			b.records[i] = out
			return out, nil
		}
	}
	b.records = append(b.records, out)
	return out, nil
}

// Retrieve returns up to TopKPerType records per type, optionally filtered by Query (substring match).
// Order: by type (episodic, semantic, procedural), then by UpdatedAt desc within each type.
func (s *Store) Retrieve(ctx context.Context, key engram.UserKey, opts engram.RetrieveOptions) ([]*engram.Record, error) {
	if err := key.CheckUserKey(); err != nil {
		return nil, err
	}

	topK := opts.TopKPerType
	if topK <= 0 {
		topK = engram.DefaultRetrieveOptions().TopKPerType
	}
	types := opts.Types
	if len(types) == 0 {
		types = []engram.MemoryType{engram.TypeEpisodic, engram.TypeSemantic, engram.TypeProcedural}
	}
	query := strings.TrimSpace(strings.ToLower(opts.Query))

	b := s.getBucket(key)
	b.mu.RLock()
	records := make([]*engram.Record, len(b.records))
	copy(records, b.records)
	b.mu.RUnlock()

	// Filter by type and optionally by query
	byType := make(map[engram.MemoryType][]*engram.Record)
	for _, r := range records {
		ok := false
		for _, t := range types {
			if r.Type == t {
				ok = true
				break
			}
		}
		if !ok {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(r.Content), query) && !strings.Contains(strings.ToLower(r.Title), query) {
			continue
		}
		byType[r.Type] = append(byType[r.Type], r)
	}

	// Sort each type by UpdatedAt desc, take top K
	var out []*engram.Record
	for _, t := range types {
		list := byType[t]
		sort.Slice(list, func(i, j int) bool {
			return list[i].UpdatedAt.After(list[j].UpdatedAt)
		})
		for i := 0; i < topK && i < len(list); i++ {
			out = append(out, list[i])
		}
	}
	return out, nil
}

// Clear removes all records for the user.
func (s *Store) Clear(ctx context.Context, key engram.UserKey) error {
	if err := key.CheckUserKey(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if app, ok := s.users[key.AppName]; ok {
		delete(app, key.UserID)
		if len(app) == 0 {
			delete(s.users, key.AppName)
		}
	}
	return nil
}
