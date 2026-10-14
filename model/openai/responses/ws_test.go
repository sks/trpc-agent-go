//
// Tencent is pleased to support the open source community by making
// trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package responses

import (
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/responses"
	"github.com/stretchr/testify/require"
)

func TestCreateEventFromParams(t *testing.T) {
	params := responses.ResponseNewParams{
		Model: "gpt-6-astra",
		Store: openai.Bool(false),
		Input: responses.ResponseNewParamsInputUnion{
			OfString: openai.String("hello"),
		},
	}
	event, err := createEventFromParams(params)
	require.NoError(t, err)
	require.Equal(t, "gpt-6-astra", event.Model)
	require.False(t, event.Stream.Valid())
	require.False(t, event.Background.Valid())
}
