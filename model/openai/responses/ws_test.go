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
	"encoding/json"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/param"
	"github.com/openai/openai-go/v3/responses"
	"github.com/stretchr/testify/require"
)

func TestCreateEventFromParams_StringInput(t *testing.T) {
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
	require.False(t, param.IsOmitted(event.Input.OfString))
	require.Equal(t, "hello", event.Input.OfString.Value)
}

func TestCreateEventFromParams_InputItemList(t *testing.T) {
	params := responses.ResponseNewParams{
		Model: "gpt-6-astra",
		Store: openai.Bool(false),
		Input: responses.ResponseNewParamsInputUnion{
			OfInputItemList: responses.ResponseInputParam{
				responses.ResponseInputItemParamOfMessage("plan a sprint", responses.EasyInputMessageRoleUser),
			},
		},
	}
	event, err := createEventFromParams(params)
	require.NoError(t, err)
	require.NotNil(t, event.Input.OfResponse)
	require.Len(t, *event.Input.OfResponse, 1)

	raw, err := json.Marshal(event)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"role":"user"`)
	require.NotContains(t, string(raw), `"input":null`)
}
