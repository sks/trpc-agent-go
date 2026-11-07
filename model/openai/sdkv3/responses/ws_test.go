//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2026 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package responses

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/packages/param"
	"github.com/openai/openai-go/v3/responses"
	"github.com/stretchr/testify/require"
	"trpc.group/trpc-go/trpc-agent-go/model"
)

func TestCreateEventFromParamsPreservesNativeInput(t *testing.T) {
	params := responses.ResponseNewParams{
		Model: "gpt-5", Store: openai.Bool(false),
		Input: responses.ResponseNewParamsInputUnion{OfInputItemList: responses.ResponseInputParam{
			responses.ResponseInputItemParamOfMessage("hi", responses.EasyInputMessageRoleUser),
		}},
	}
	event, err := createEventFromParams(params)
	require.NoError(t, err)
	require.False(t, event.Stream.Valid())
	require.False(t, event.Background.Valid())
	require.NotNil(t, event.Input.OfResponse)
	require.Len(t, *event.Input.OfResponse, 1)
	raw, err := json.Marshal(event)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"role":"user"`)
	require.NotContains(t, string(raw), `"input":null`)

	params.Input = responses.ResponseNewParamsInputUnion{OfString: openai.String("hello")}
	event, err = createEventFromParams(params)
	require.NoError(t, err)
	require.False(t, param.IsOmitted(event.Input.OfString))
	require.Equal(t, "hello", event.Input.OfString.Value)
}

func TestWebSocketSteerCommitsOnlySuccessorNativeOutput(t *testing.T) {
	const firstItem = `{"type":"message","id":"msg_old","status":"completed","role":"assistant","content":[{"type":"output_text","text":"old"}]}`
	const finalItem = `{"type":"message","id":"msg_new","status":"completed","role":"assistant","content":[{"type":"output_text","text":"new"}],"future_field":"opaque"}`
	var mu sync.Mutex
	var callbacks []MidTurnSession
	var capturedCreate map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		_ = json.Unmarshal(data, &capturedCreate)
		write := func(s string) bool { return conn.Write(ctx, websocket.MessageText, []byte(s)) == nil }
		if !write(`{"type":"response.created","response":{"id":"resp_old","status":"in_progress"}}`) {
			return
		}
		if !write(`{"type":"response.output_text.delta","delta":"old preview"}`) {
			return
		}
		_, data, err = conn.Read(ctx)
		if err != nil {
			return
		}
		var steer map[string]json.RawMessage
		_ = json.Unmarshal(data, &steer)
		if string(steer["type"]) != `"response.steer"` || string(steer["previous_response_id"]) != `"resp_old"` {
			return
		}
		if !write(`{"type":"response.steer.accepted"}`) {
			return
		}
		if !write(`{"type":"response.incomplete","response":{"id":"resp_old","status":"incomplete","incomplete_details":{"reason":"steered"},"output":[` + firstItem + `]}}`) {
			return
		}
		if !write(`{"type":"response.created","response":{"id":"resp_new","status":"in_progress"}}`) {
			return
		}
		if !write(`{"type":"response.output_item.done","output_index":0,"item":` + finalItem + `}`) {
			return
		}
		if write(`{"type":"response.completed","response":{"id":"resp_new","status":"completed","output":[` + finalItem + `]}}`) {
			_, _, _ = conn.Read(ctx) // Wait for the client to finish consuming the terminal event.
		}
	}))
	defer srv.Close()

	ready := make(chan MidTurnSession, 1)
	m := New("gpt-5", WithAPIKey("test"), WithBaseURL(srv.URL), WithWebSocket(true),
		WithSteerSessionCallback(func(_ context.Context, s MidTurnSession) {
			mu.Lock()
			callbacks = append(callbacks, s)
			mu.Unlock()
			if s != nil {
				ready <- s
			}
		}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := m.GenerateContent(ctx, &model.Request{GenerationConfig: model.GenerationConfig{Stream: true}, Messages: []model.Message{model.NewUserMessage("hi")}})
	require.NoError(t, err)
	session := <-ready
	for session.ResponseID() == "" {
		select {
		case <-ctx.Done():
			t.Fatal("response id not received")
		case <-time.After(time.Millisecond):
		}
	}
	require.Equal(t, "resp_old", session.ResponseID())
	require.NoError(t, session.Steer(ctx, "new input"))
	got := collect(t, ch)
	require.Len(t, got, 2)
	require.True(t, got[0].IsPartial)
	require.Nil(t, got[0].Choices[0].Delta.ProviderData)
	require.False(t, got[0].Done)
	final := got[1]
	require.Equal(t, "resp_new", final.ID)
	require.Nil(t, final.Error)
	require.Equal(t, "new", final.Choices[0].Message.Content)
	require.JSONEq(t, `[`+finalItem+`]`, string(final.Choices[0].Message.ProviderData.Payload))
	require.Equal(t, responseProvider, final.Choices[0].Message.ProviderData.Protocol)
	require.Equal(t, "gpt-5", final.Choices[0].Message.ProviderData.Model)
	require.ErrorContains(t, session.Steer(ctx, "after close"), "closed")
	mu.Lock()
	require.Len(t, callbacks, 2)
	require.Nil(t, callbacks[1])
	mu.Unlock()
	require.Equal(t, `"response.create"`, string(capturedCreate["type"]))
	require.Equal(t, "false", string(capturedCreate["store"]))
	require.JSONEq(t, `["reasoning.encrypted_content"]`, string(capturedCreate["include"]))
	require.NotContains(t, capturedCreate, "previous_response_id")
}

func TestWebSocketErrorPreservesProviderMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if _, _, err := conn.Read(ctx); err != nil {
			return
		}
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"error","status":400,"error":{"type":"invalid_request_error","code":"unsupported_parameter","param":"tools","message":"This model does not support tools on WebSocket"}}`))
	}))
	defer srv.Close()

	m := New("gpt-6-astra", WithAPIKey("test"), WithBaseURL(srv.URL), WithWebSocket(true))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := m.GenerateContent(ctx, &model.Request{
		GenerationConfig: model.GenerationConfig{Stream: true},
		Messages:         []model.Message{model.NewUserMessage("hi")},
	})
	require.NoError(t, err)
	got := collect(t, ch)
	require.Len(t, got, 1)
	require.Empty(t, got[0].Choices)
	require.Equal(t, "This model does not support tools on WebSocket", got[0].Error.Message)
	require.Equal(t, "unsupported_parameter", *got[0].Error.Code)
	require.Equal(t, "tools", *got[0].Error.Param)
}

func TestWebSocketSteerPendingCannotCommitToolCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if _, _, err := conn.Read(ctx); err != nil {
			return
		}
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.created","response":{"id":"resp_1","status":"in_progress"}}`))
		_ = conn.Write(ctx, websocket.MessageText, []byte(`{"type":"response.steer.pending"}`))
	}))
	defer srv.Close()
	m := New("gpt-5", WithAPIKey("test"), WithBaseURL(srv.URL), WithWebSocket(true))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := m.GenerateContent(ctx, &model.Request{GenerationConfig: model.GenerationConfig{Stream: true}, Messages: []model.Message{model.NewUserMessage("hi")}})
	require.NoError(t, err)
	got := collect(t, ch)
	require.Len(t, got, 1)
	require.ErrorContains(t, errorFromResponse(got[0]), "response.steer.pending")
	require.Empty(t, got[0].Choices)
}

func errorFromResponse(r *model.Response) error {
	if r.Error == nil {
		return nil
	}
	return &responseErrorString{r.Error.Message}
}

type responseErrorString struct{ message string }

func (e *responseErrorString) Error() string { return e.message }
