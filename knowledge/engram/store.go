//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package engram

import "context"

// Store is the ENGRAM memory store: add typed records and retrieve top-k per type (optionally query-scoped).
type Store interface {
	// Add adds or updates a typed memory record. If ID is empty, a new ID is generated.
	// Same (appName, userID, type, content) may be idempotent depending on implementation.
	Add(ctx context.Context, key UserKey, record Record) (*Record, error)

	// Retrieve returns relevant records per type, merged. Options control top-k per type and optional query.
	// Order is implementation-defined (e.g. episodic by time, semantic by relevance).
	Retrieve(ctx context.Context, key UserKey, opts RetrieveOptions) ([]*Record, error)

	// Clear removes all records for the user. Optional; not all implementations may support it.
	Clear(ctx context.Context, key UserKey) error
}
