//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//
//

package tool

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestStreamableTool_Interface(t *testing.T) {
	// Compile-time check
	var _ StreamableTool = (*testStreamableTool)(nil)
}

type testStreamableTool struct{}

func (d *testStreamableTool) StreamableCall(ctx context.Context, jsonArgs []byte) (*StreamReader, error) {
	s := NewStream(1)
	go func() {
		defer s.Writer.Close()
		s.Writer.Send(StreamChunk{Content: "test", Metadata: Metadata{CreatedAt: time.Now()}}, nil)
		s.Writer.Send(StreamChunk{Content: "more data"}, nil)
		s.Writer.Send(StreamChunk{Content: "final chunk"}, nil)

	}()
	return s.Reader, nil
}
func (d *testStreamableTool) Declaration() *Declaration {
	return &Declaration{
		Name:        "TestStreamableTool",
		Description: "A test tool for streaming data.",
		InputSchema: &Schema{
			Type:        "object",
			Properties:  map[string]*Schema{"input": {Type: "string"}},
			Required:    []string{"input"},
			Description: "Input for the test streamable tool.",
		},
	}
}

func TestSchemaPatternJSON(t *testing.T) {
	schema := &Schema{Type: "string", Pattern: "^[a-z0-9_-]+$"}
	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	if string(data) != `{"type":"string","pattern":"^[a-z0-9_-]+$"}` {
		t.Fatalf("unexpected schema JSON: %s", string(data))
	}

	var roundTrip Schema
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	if roundTrip.Pattern != schema.Pattern {
		t.Fatalf("pattern = %q, want %q", roundTrip.Pattern, schema.Pattern)
	}
}

func TestSchemaValidationKeywordsJSON(t *testing.T) {
	minLength := uint64(0)
	maxLength := uint64(100)
	schema := &Schema{
		Type:             "object",
		Format:           "custom-object",
		MinLength:        &minLength,
		MaxLength:        &maxLength,
		Minimum:          json.Number("0"),
		Maximum:          json.Number("20"),
		ExclusiveMinimum: json.Number("-1.5"),
		ExclusiveMaximum: json.Number("20.5"),
	}

	data, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}

	var encoded map[string]any
	if err := json.Unmarshal(data, &encoded); err != nil {
		t.Fatalf("unmarshal encoded schema: %v", err)
	}
	if encoded["format"] != "custom-object" {
		t.Fatalf("format = %v, want custom-object", encoded["format"])
	}
	if encoded["minLength"] != float64(0) || encoded["maxLength"] != float64(100) {
		t.Fatalf("length bounds = (%v, %v), want (0, 100)", encoded["minLength"], encoded["maxLength"])
	}
	if encoded["minimum"] != float64(0) || encoded["maximum"] != float64(20) {
		t.Fatalf("numeric bounds = (%v, %v), want (0, 20)", encoded["minimum"], encoded["maximum"])
	}
	if encoded["exclusiveMinimum"] != -1.5 || encoded["exclusiveMaximum"] != 20.5 {
		t.Fatalf("exclusive bounds = (%v, %v), want (-1.5, 20.5)", encoded["exclusiveMinimum"], encoded["exclusiveMaximum"])
	}

	var roundTrip Schema
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	if roundTrip.MinLength == nil || *roundTrip.MinLength != 0 {
		t.Fatalf("minLength = %v, want pointer to zero", roundTrip.MinLength)
	}
	if roundTrip.Maximum != json.Number("20") {
		t.Fatalf("maximum = %q, want 20", roundTrip.Maximum)
	}
}
