//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package engram

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemoryType_Valid(t *testing.T) {
	assert.True(t, TypeEpisodic.Valid())
	assert.True(t, TypeSemantic.Valid())
	assert.True(t, TypeProcedural.Valid())
	assert.False(t, MemoryType("").Valid())
	assert.False(t, MemoryType("other").Valid())
}

func TestParseMemoryType(t *testing.T) {
	for _, c := range []struct {
		in   string
		want MemoryType
		ok   bool
	}{
		{"episodic", TypeEpisodic, true},
		{"Episodic", TypeEpisodic, true},
		{"semantic", TypeSemantic, true},
		{"procedural", TypeProcedural, true},
		{"", TypeEpisodic, false},
		{"x", TypeEpisodic, false},
	} {
		got, ok := ParseMemoryType(c.in)
		assert.Equal(t, c.want, got, "input %q", c.in)
		assert.Equal(t, c.ok, ok, "input %q", c.in)
	}
}

func TestUserKey_CheckUserKey(t *testing.T) {
	// UserKey is memory.UserKey; CheckUserKey has pointer receiver.
	assert.NoError(t, (&UserKey{AppName: "a", UserID: "u"}).CheckUserKey())
	assert.ErrorIs(t, (&UserKey{AppName: "", UserID: "u"}).CheckUserKey(), ErrAppNameRequired)
	assert.ErrorIs(t, (&UserKey{AppName: "a", UserID: ""}).CheckUserKey(), ErrUserIDRequired)
}
