//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//
//

package mcp

import (
	"encoding/json"

	"trpc.group/trpc-go/trpc-agent-go/tool"
)

// convertMCPSchemaToSchema converts MCP's JSON schema to our Schema format.
// tool.NormalizeSchema first rewrites the decoded schema into the keyword
// subset tool.Schema can hold, so every keyword the type has a field for
// survives at every nesting level: properties, items, $defs,
// additionalProperties and the root all get the same treatment, oneOf becomes
// anyOf, const becomes a one-value enum, tuple items become a single items
// choice, and allOf members merge. Keywords whose value has the wrong JSON
// shape are dropped rather than failing the whole schema. The source schema
// is never mutated.
func convertMCPSchemaToSchema(mcpSchema any) *tool.Schema {
	schemaBytes, err := json.Marshal(mcpSchema)
	if err != nil {
		return &tool.Schema{
			Type: "object",
		}
	}

	var schemaMap map[string]any
	if err := json.Unmarshal(schemaBytes, &schemaMap); err != nil {
		return &tool.Schema{
			Type: "object",
		}
	}

	normalized, _ := tool.NormalizeSchema(schemaMap)
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return &tool.Schema{
			Type: "object",
		}
	}
	schema := &tool.Schema{}
	if err := json.Unmarshal(encoded, schema); err != nil {
		return &tool.Schema{
			Type: "object",
		}
	}
	return schema
}
