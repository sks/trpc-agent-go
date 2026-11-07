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
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/packages/param"
	"github.com/openai/openai-go/v3/responses"
	"trpc.group/trpc-go/trpc-agent-go/model"
)

const (
	eventResponseSteerAccepted = "response.steer.accepted"
	eventResponseSteerFailed   = "response.steer.failed"
	eventResponseSteerPending  = "response.steer.pending"
	incompleteReasonSteered    = "steered"
)

// MidTurnSession steers an in-flight Responses WebSocket generation. A session
// is valid only until its streaming call ends; ResponseID is empty until the
// provider sends response.created. Steer requires a nonempty input and a ready ID.
type MidTurnSession interface {
	Steer(ctx context.Context, input string) error
	ResponseID() string
}

// SteerSessionCallback receives the live session for one WebSocket streaming
// call and then nil when it ends. Callbacks for concurrent calls may overlap.
type SteerSessionCallback func(ctx context.Context, session MidTurnSession)

type midTurnSession struct {
	mu         sync.Mutex
	conn       *responses.ResponseConnection
	responseID string
	steered    bool
	closed     bool
}

func (s *midTurnSession) ResponseID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.responseID
}

func (s *midTurnSession) setResponseID(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != "" {
		s.responseID = id
	}
}

func (s *midTurnSession) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
}

func (s *midTurnSession) hasSteered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.steered
}

func (s *midTurnSession) Steer(ctx context.Context, input string) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return errors.New("openai/responses: empty steer input")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.conn == nil {
		return errors.New("openai/responses: mid-turn session closed")
	}
	if s.responseID == "" {
		return errors.New("openai/responses: response id not ready for steer")
	}
	if err := s.conn.Send(ctx, responses.ResponsesClientEventParamOfResponseSteer(input, s.responseID)); err != nil {
		return fmt.Errorf("openai/responses: send response.steer: %w", err)
	}
	s.steered = true
	return nil
}

// Each request owns its own socket: sdkv3 sends complete client-managed history
// and does not use previous_response_id or server-side tool continuation.
func (m *Model) handleWebSocketStreaming(
	ctx context.Context,
	params responses.ResponseNewParams,
	opts []option.RequestOption,
	emit func(*model.Response) bool,
) {
	conn, err := m.client.Responses.Connect(ctx, responses.ResponseConnectionOptions{}, opts...)
	if err != nil {
		if ctx.Err() == nil {
			// No command was sent, so HTTP streaming is safe to retry.
			m.handleStreaming(ctx, params, opts, emit)
		}
		return
	}
	defer conn.Close()

	createEvent, err := createEventFromParams(params)
	if err != nil {
		emit(apiErrorResponse(err))
		return
	}
	session := &midTurnSession{conn: conn}
	if m.steerCallback != nil {
		m.steerCallback(ctx, session)
	}
	defer func() {
		session.close()
		if m.steerCallback != nil {
			m.steerCallback(ctx, nil)
		}
	}()
	if err := conn.Create(ctx, createEvent); err != nil {
		if ctx.Err() == nil {
			emit(apiErrorResponse(fmt.Errorf("openai/responses: websocket response.create: %w", err)))
		}
		return
	}

	acc := &streamAccumulator{doneItems: make(map[int64]responses.ResponseOutputItemUnion)}
	var initialID, successorID string
	steerAccepted := false
	awaitingSuccessor := false
	for {
		if ctx.Err() != nil {
			return
		}
		event, err := conn.Recv(ctx)
		if err != nil {
			if ctx.Err() == nil {
				emit(apiErrorResponse(fmt.Errorf("openai/responses: websocket receive: %w", err)))
			}
			return
		}
		switch event.Type {
		case eventResponseSteerAccepted:
			steerAccepted = true
			continue
		case eventResponseSteerFailed:
			emit(apiErrorResponse(errors.New("openai/responses: response.steer.failed")))
			return
		case eventResponseSteerPending:
			// A pending steer needs server-side tool/approval continuation, which
			// cannot be replayed by this client-managed-history adapter.
			emit(apiErrorResponse(errors.New("openai/responses: response.steer.pending requires unsupported server-side continuation")))
			return
		}
		var streamEvent responses.ResponseStreamEventUnion
		if err := json.Unmarshal([]byte(event.RawJSON()), &streamEvent); err != nil || streamEvent.Type == "" {
			emit(apiErrorResponse(fmt.Errorf("openai/responses: decode websocket event %q: %v", event.Type, err)))
			return
		}
		if event.Type == eventResponseCreated {
			id := streamEvent.Response.ID
			if id == "" {
				emit(apiErrorResponse(errors.New("openai/responses: websocket response.created has no id")))
				return
			}
			if initialID == "" {
				initialID = id
			} else if id != initialID {
				if successorID != "" && id != successorID {
					emit(apiErrorResponse(errors.New("openai/responses: unexpected websocket successor response")))
					return
				}
				successorID = id
				acc = &streamAccumulator{doneItems: make(map[int64]responses.ResponseOutputItemUnion)}
			}
			session.setResponseID(id)
		}
		if event.Type == eventResponseIncomplete && streamEvent.Response.ID == initialID &&
			string(streamEvent.Response.IncompleteDetails.Reason) == incompleteReasonSteered {
			// The original was interrupted; only a completed successor can be
			// committed. Its own output events will start a new accumulator.
			awaitingSuccessor = true
			continue
		}
		if event.Type == eventResponseCompleted && streamEvent.Response.ID == initialID &&
			(steerAccepted || session.hasSteered()) {
			// A sent steer may race with the original completion. Wait for an
			// explicit successor or surface EOF, not stale native output.
			awaitingSuccessor = true
			continue
		}
		if awaitingSuccessor && successorID == "" && event.Type != eventResponseCreated {
			// Ignore any remaining original response events while waiting for
			// the new response.created to establish the successor ID.
			continue
		}
		if successorID != "" && streamEvent.Response.ID == initialID &&
			(event.Type == eventResponseCompleted || event.Type == eventResponseIncomplete) {
			continue
		}
		terminal, keepGoing := handleStreamEvent(m.name, acc, &streamEvent, emit)
		if terminal || !keepGoing {
			return
		}
	}
}

func createEventFromParams(params responses.ResponseNewParams) (responses.ResponsesClientEventResponseCreateParam, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return responses.ResponsesClientEventResponseCreateParam{}, fmt.Errorf("openai/responses: marshal websocket create params: %w", err)
	}
	var event responses.ResponsesClientEventResponseCreateParam
	if err := json.Unmarshal(raw, &event); err != nil {
		return responses.ResponsesClientEventResponseCreateParam{}, fmt.Errorf("openai/responses: decode websocket create params: %w", err)
	}
	event.Stream = param.Opt[bool]{}
	event.Background = param.Opt[bool]{}
	// The HTTP and WS input unions serialize the same items but use different
	// variant fields; JSON round-tripping the HTTP union would lose the input.
	if !param.IsOmitted(params.Input.OfString) {
		event.Input = responses.ResponsesClientEventResponseCreateInputUnionParam{OfString: params.Input.OfString}
	} else if params.Input.OfInputItemList != nil {
		items := params.Input.OfInputItemList
		event.Input = responses.ResponsesClientEventResponseCreateInputUnionParam{OfResponse: &items}
	}
	return event, nil
}
