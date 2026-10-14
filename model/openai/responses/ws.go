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

// MidTurnSession steers an in-flight Responses WebSocket generation.
// Genie registers this with runsteer so /api/v1/inject can call response.steer.
type MidTurnSession interface {
	Steer(ctx context.Context, input string) error
	ResponseID() string
}

// SteerSessionCallback is invoked once response.created yields an ID so hosts
// can attach MidTurnSession to an active run. Cleared when the session ends.
type SteerSessionCallback func(ctx context.Context, session MidTurnSession)

// midTurnSession is the live steerer for one WebSocket GenerateContent call.
type midTurnSession struct {
	mu         sync.Mutex
	conn       *responses.ResponseConnection
	responseID string
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

// Steer sends response.steer on the open WebSocket connection.
func (s *midTurnSession) Steer(ctx context.Context, input string) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return fmt.Errorf("openai/responses: empty steer input")
	}
	s.mu.Lock()
	conn := s.conn
	id := s.responseID
	closed := s.closed
	s.mu.Unlock()
	if closed || conn == nil {
		return fmt.Errorf("openai/responses: mid-turn session closed")
	}
	if id == "" {
		return fmt.Errorf("openai/responses: response id not ready for steer")
	}
	err := conn.Send(ctx, responses.ResponsesClientEventParamOfResponseSteer(input, id))
	if err != nil {
		return fmt.Errorf("openai/responses: send response.steer: %w", err)
	}
	return nil
}

func (m *Model) handleStreamingOrWS(
	ctx context.Context,
	params responses.ResponseNewParams,
	opts []option.RequestOption,
	emit func(*model.Response) bool,
) {
	if !m.useWebSocket {
		m.handleStreaming(ctx, params, opts, emit)
		return
	}
	if err := m.handleWebSocketStreaming(ctx, params, opts, emit); err != nil {
		// Fall back to HTTP SSE when Connect fails or the model rejects WS.
		if ctx.Err() != nil {
			return
		}
		m.handleStreaming(ctx, params, opts, emit)
	}
}

func (m *Model) handleWebSocketStreaming(
	ctx context.Context,
	params responses.ResponseNewParams,
	opts []option.RequestOption,
	emit func(*model.Response) bool,
) error {
	conn, reused, err := m.acquireWSConn(ctx, opts)
	if err != nil {
		return err
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
		if !m.retainWSConn(conn) {
			_ = conn.Close()
		}
	}()

	createEvent, err := createEventFromParams(params)
	if err != nil {
		return err
	}
	if reused && m.stickyPreviousID != "" {
		createEvent.PreviousResponseID = param.NewOpt(m.stickyPreviousID)
	}
	if err := conn.Create(ctx, createEvent); err != nil {
		m.clearStickyWS()
		return fmt.Errorf("openai/responses: websocket response.create: %w", err)
	}

	acc := &streamAccumulator{}
	initialID := ""
	successorID := ""
	emittedTerminal := false
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		event, recvErr := conn.Recv(ctx)
		if recvErr != nil {
			m.clearStickyWS()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if !emittedTerminal {
				emit(apiErrorResponse(recvErr))
			}
			return nil
		}
		streamEvent, ok := wsEventToStreamEvent(event)
		if ok {
			m.runStreamCallback(ctx, &params, &streamEvent)
		}
		switch event.Type {
		case eventResponseCreated:
			id := wsResponseID(event)
			session.setResponseID(id)
			if initialID == "" {
				initialID = id
			} else if successorID == "" && id != initialID {
				successorID = id
			}
			if ok {
				_ = handleStreamEvent(m.name, acc, &streamEvent, emit)
			}
		case eventResponseSteerAccepted:
			// Queued only; keep reading for the automatic continuation.
		case eventResponseSteerFailed:
			if !emittedTerminal {
				emit(apiErrorResponse(errors.New("openai/responses: response.steer.failed")))
				emittedTerminal = true
			}
			m.clearStickyWS()
			return nil
		case eventResponseSteerPending:
			// Tool/approval input required before the queued steer can apply.
			// Keep the connection sticky so the next GenerateContent can return
			// function_call_output on the same socket (Phase 3).
			m.stickyPreviousID = session.ResponseID()
			if m.stickyPreviousID == "" {
				m.stickyPreviousID = initialID
			}
			m.keepWSConn = true
			if !emittedTerminal {
				if ok && !handleStreamEvent(m.name, acc, &streamEvent, emit) {
					return nil
				}
				// Prefer a tool-call completion from the accumulator so the host
				// tool loop runs and resumes via sticky WS.
				if len(acc.calls) > 0 {
					emit(projectAccumulator(m.name, acc, "completed", nil))
				} else if ok {
					emit(projectAccumulator(m.name, acc, "incomplete", nil))
				}
				emittedTerminal = true
			}
			return nil
		case eventResponseIncomplete:
			reason := wsIncompleteReason(event)
			id := wsResponseID(event)
			if reason == incompleteReasonSteered && id == initialID {
				// Original interrupted by steer; wait for successor.
				if ok {
					_ = handleStreamEvent(m.name, acc, &streamEvent, func(*model.Response) bool { return true })
				}
				acc = &streamAccumulator{}
				continue
			}
			if ok && !emittedTerminal {
				emittedTerminal = true
				if !handleStreamEvent(m.name, acc, &streamEvent, emit) {
					return nil
				}
			}
			m.clearStickyWS()
			return nil
		case eventResponseCompleted:
			id := wsResponseID(event)
			if successorID != "" && id != successorID && id == initialID {
				// Completed before steer applied; still may get a successor.
				if ok {
					_ = handleStreamEvent(m.name, acc, &streamEvent, func(*model.Response) bool { return true })
				}
				continue
			}
			if ok && !emittedTerminal {
				emittedTerminal = true
				if !handleStreamEvent(m.name, acc, &streamEvent, emit) {
					return nil
				}
			}
			// Tool calls: keep sticky so the next turn can continue on WS.
			if len(acc.calls) > 0 {
				m.stickyPreviousID = id
				m.keepWSConn = true
			} else {
				m.clearStickyWS()
			}
			return nil
		case eventResponseFailed, eventError:
			if ok && !emittedTerminal {
				emittedTerminal = true
				_ = handleStreamEvent(m.name, acc, &streamEvent, emit)
			} else if !emittedTerminal {
				emit(apiErrorResponse(errors.New("openai/responses: websocket response failed")))
				emittedTerminal = true
			}
			m.clearStickyWS()
			return nil
		default:
			if ok && !emittedTerminal {
				if !handleStreamEvent(m.name, acc, &streamEvent, emit) {
					return nil
				}
			}
		}
	}
}

func (m *Model) acquireWSConn(ctx context.Context, opts []option.RequestOption) (*responses.ResponseConnection, bool, error) {
	m.wsMu.Lock()
	defer m.wsMu.Unlock()
	if m.wsConn != nil && m.keepWSConn {
		return m.wsConn, true, nil
	}
	if m.wsConn != nil {
		_ = m.wsConn.Close()
		m.wsConn = nil
	}
	conn, err := m.client.Responses.Connect(ctx, responses.ResponseConnectionOptions{}, opts...)
	if err != nil {
		return nil, false, fmt.Errorf("openai/responses: websocket connect: %w", err)
	}
	m.wsConn = conn
	m.keepWSConn = false
	m.stickyPreviousID = ""
	return conn, false, nil
}

func (m *Model) retainWSConn(conn *responses.ResponseConnection) bool {
	m.wsMu.Lock()
	defer m.wsMu.Unlock()
	if m.keepWSConn && m.wsConn == conn {
		return true
	}
	if m.wsConn == conn {
		m.wsConn = nil
	}
	return false
}

func (m *Model) clearStickyWS() {
	m.wsMu.Lock()
	defer m.wsMu.Unlock()
	m.keepWSConn = false
	m.stickyPreviousID = ""
	if m.wsConn != nil {
		_ = m.wsConn.Close()
		m.wsConn = nil
	}
}

func createEventFromParams(params responses.ResponseNewParams) (responses.ResponsesClientEventResponseCreateParam, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return responses.ResponsesClientEventResponseCreateParam{}, fmt.Errorf("marshal create params: %w", err)
	}
	var event responses.ResponsesClientEventResponseCreateParam
	if err := json.Unmarshal(raw, &event); err != nil {
		return responses.ResponsesClientEventResponseCreateParam{}, fmt.Errorf("unmarshal create event: %w", err)
	}
	// WebSocket create must not set HTTP stream/background transport fields.
	event.Stream = param.Opt[bool]{}
	event.Background = param.Opt[bool]{}
	return event, nil
}

func wsEventToStreamEvent(event responses.ResponsesServerEventUnion) (responses.ResponseStreamEventUnion, bool) {
	raw := event.RawJSON()
	if raw == "" {
		return responses.ResponseStreamEventUnion{}, false
	}
	var streamEvent responses.ResponseStreamEventUnion
	if err := json.Unmarshal([]byte(raw), &streamEvent); err != nil {
		return responses.ResponseStreamEventUnion{}, false
	}
	return streamEvent, streamEvent.Type != ""
}

func wsResponseID(event responses.ResponsesServerEventUnion) string {
	switch event.Type {
	case eventResponseCreated:
		return event.OfResponsesServerEventResponseWsCreated.Response.ID
	case eventResponseCompleted:
		return event.OfResponsesServerEventResponseWsCompleted.Response.ID
	case eventResponseIncomplete:
		return event.OfResponsesServerEventResponseWsIncomplete.Response.ID
	case eventResponseFailed:
		return event.OfResponsesServerEventResponseWsFailed.Response.ID
	default:
		var envelope struct {
			Response struct {
				ID string `json:"id"`
			} `json:"response"`
		}
		_ = json.Unmarshal([]byte(event.RawJSON()), &envelope)
		return envelope.Response.ID
	}
}

func wsIncompleteReason(event responses.ResponsesServerEventUnion) string {
	if event.Type != eventResponseIncomplete {
		return ""
	}
	r := event.OfResponsesServerEventResponseWsIncomplete.Response
	return string(r.IncompleteDetails.Reason)
}
