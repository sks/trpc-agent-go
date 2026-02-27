//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package inmemory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"trpc.group/trpc-go/trpc-agent-go/knowledge/engram"
)

func TestStore_Add_Retrieve_Clear(t *testing.T) {
	ctx := context.Background()
	store := New()
	key := engram.UserKey{AppName: "app1", UserID: "user1"}

	// Add episodic and semantic
	r1, err := store.Add(ctx, key, engram.Record{
		Type:    engram.TypeEpisodic,
		Content: "User asked about login.",
		Title:   "Login question",
	})
	require.NoError(t, err)
	require.NotEmpty(t, r1.ID)
	assert.Equal(t, engram.TypeEpisodic, r1.Type)
	assert.Equal(t, "User asked about login.", r1.Content)

	_, err = store.Add(ctx, key, engram.Record{
		Type:    engram.TypeSemantic,
		Content: "User prefers dark mode.",
	})
	require.NoError(t, err)

	_, err = store.Add(ctx, key, engram.Record{
		Type:    engram.TypeEpisodic,
		Content: "User ran the deploy command.",
	})
	require.NoError(t, err)

	// Retrieve: top 2 per type
	opts := engram.RetrieveOptions{TopKPerType: 2}
	recs, err := store.Retrieve(ctx, key, opts)
	require.NoError(t, err)
	// Should have 2 episodic + 2 semantic (we only have 2 episodic, 1 semantic)
	assert.GreaterOrEqual(t, len(recs), 2)
	assert.LessOrEqual(t, len(recs), 4)

	// Clear
	require.NoError(t, store.Clear(ctx, key))
	recs, err = store.Retrieve(ctx, key, opts)
	require.NoError(t, err)
	assert.Empty(t, recs)
}

func TestStore_Add_Validation(t *testing.T) {
	ctx := context.Background()
	store := New()
	key := engram.UserKey{AppName: "a", UserID: "u"}

	_, err := store.Add(ctx, engram.UserKey{}, engram.Record{Type: engram.TypeEpisodic, Content: "x"})
	require.Error(t, err)

	_, err = store.Add(ctx, key, engram.Record{Type: engram.TypeEpisodic, Content: ""})
	require.ErrorIs(t, err, engram.ErrRecordContentRequired)

	_, err = store.Add(ctx, key, engram.Record{Type: engram.MemoryType("invalid"), Content: "x"})
	require.ErrorIs(t, err, engram.ErrInvalidMemoryType)
}

func TestStore_Retrieve_QueryFilter(t *testing.T) {
	ctx := context.Background()
	store := New()
	key := engram.UserKey{AppName: "app", UserID: "u"}

	_, _ = store.Add(ctx, key, engram.Record{Type: engram.TypeSemantic, Content: "User likes pizza."})
	_, _ = store.Add(ctx, key, engram.Record{Type: engram.TypeSemantic, Content: "User prefers coffee."})

	opts := engram.RetrieveOptions{TopKPerType: 5, Query: "pizza", Types: []engram.MemoryType{engram.TypeSemantic}}
	recs, err := store.Retrieve(ctx, key, opts)
	require.NoError(t, err)
	require.Len(t, recs, 1)
	assert.Contains(t, recs[0].Content, "pizza")
}
