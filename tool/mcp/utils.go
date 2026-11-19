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
	"reflect"

	"trpc.group/trpc-go/trpc-agent-go/tool"
)

// convertMCPSchemaToSchema converts MCP's JSON schema to our Schema format.
// The decoded schema is normalized into the keyword subset tool.Schema can
// hold, and then decoded into the struct, so every keyword the type has a
// field for survives at every nesting level: properties, items, $defs,
// additionalProperties and the root all get the same treatment. Keywords the
// type cannot hold are rewritten to the closest representable form instead of
// being dropped: oneOf becomes anyOf, const becomes a one-value enum, tuple
// items become a single items choice, and allOf members are merged. Keywords
// whose value has the wrong JSON shape are dropped rather than failing the
// whole schema. The source schema is never mutated: conversion works on a
// decoded copy.
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

	normalized, err := json.Marshal(normalizeJSONSchemaNode(schemaMap))
	if err != nil {
		return &tool.Schema{
			Type: "object",
		}
	}
	schema := &tool.Schema{}
	if err := json.Unmarshal(normalized, schema); err != nil {
		return &tool.Schema{
			Type: "object",
		}
	}
	return schema
}

// normalizeJSONSchemaNode rewrites one decoded JSON Schema object into the
// subset tool.Schema can hold. Children are normalized first, so allOf
// members arrive already rewritten and merging them needs no second pass.
func normalizeJSONSchemaNode(node map[string]any) map[string]any {
	normalizeObjectMap(node, "properties")
	normalizeObjectMap(node, "$defs")
	normalizeItems(node)
	normalizeAdditionalProperties(node)
	normalizeBranchList(node, "anyOf")
	normalizeBranchList(node, "oneOf")
	allOfMembers := takeObjectList(node, "allOf")

	mergeAllOf(node, allOfMembers)
	mergeOneOfIntoAnyOf(node)
	rewriteConst(node)
	rewriteTypeList(node)
	sanitizeKeywords(node)
	return node
}

// normalizeObjectMap normalizes each object value of a name-to-schema keyword
// such as properties or $defs. A boolean true is the schema for any value and
// becomes the empty schema. False and non-schema values cannot be represented
// in tool.Schema; dropping them widens what the input accepts, but keeps the
// rest of the schema instead of failing the whole conversion.
func normalizeObjectMap(node map[string]any, key string) {
	schemas, ok := node[key].(map[string]any)
	if !ok {
		delete(node, key)
		return
	}
	for name, raw := range schemas {
		switch v := raw.(type) {
		case map[string]any:
			schemas[name] = normalizeJSONSchemaNode(v)
		case bool:
			if !v {
				delete(schemas, name)
				continue
			}
			schemas[name] = map[string]any{}
		default:
			delete(schemas, name)
		}
	}
}

// normalizeItems rewrites the items keyword. Map form is normalized in place.
// Tuple form (items as a list) and prefixItems describe positions, which
// tool.Schema cannot express, so the positions collapse into one items schema
// whose anyOf accepts any position; this widens the constraint but keeps
// every position's type visible to the model. Boolean or malformed items are
// dropped: true allows anything, and false (only the empty array) has no
// representable form.
func normalizeItems(node map[string]any) {
	prefix := takeObjectList(node, "prefixItems")
	raw := node["items"]
	if len(prefix) == 0 {
		switch v := raw.(type) {
		case map[string]any:
			node["items"] = normalizeJSONSchemaNode(v)
		case []any:
			node["items"] = anyOfPositions(v)
			if node["items"] == nil {
				delete(node, "items")
			}
		default:
			delete(node, "items")
		}
		return
	}
	positions := prefix
	switch v := raw.(type) {
	case map[string]any:
		positions = append(positions, normalizeJSONSchemaNode(v))
	case []any:
		positions = append(positions, normalizedObjects(v)...)
	}
	node["items"] = map[string]any{"anyOf": positions}
}

// anyOfPositions wraps normalized tuple positions into a single items choice
// schema, or returns nil when no position is representable.
func anyOfPositions(items []any) map[string]any {
	positions := normalizedObjects(items)
	if len(positions) == 0 {
		return nil
	}
	return map[string]any{"anyOf": positions}
}

// normalizeAdditionalProperties keeps boolean values, normalizes the schema
// object form, and drops malformed values.
func normalizeAdditionalProperties(node map[string]any) {
	switch v := node["additionalProperties"].(type) {
	case map[string]any:
		node["additionalProperties"] = normalizeJSONSchemaNode(v)
	case bool:
	default:
		delete(node, "additionalProperties")
	}
}

// normalizeBranchList normalizes each object branch of an anyOf or oneOf
// keyword and drops branches that are not schema objects, including booleans,
// which tool.Schema cannot represent.
func normalizeBranchList(node map[string]any, key string) {
	raw, ok := node[key].([]any)
	if !ok {
		delete(node, key)
		return
	}
	branches := normalizedObjects(raw)
	if len(branches) == 0 {
		delete(node, key)
		return
	}
	node[key] = branches
}

// takeObjectList removes key from node and returns its object entries,
// normalized. Non-object entries are dropped.
func takeObjectList(node map[string]any, key string) []any {
	raw, ok := node[key].([]any)
	delete(node, key)
	if !ok {
		return nil
	}
	return normalizedObjects(raw)
}

// normalizedObjects returns the schema-object entries of list, normalized.
func normalizedObjects(list []any) []any {
	out := make([]any, 0, len(list))
	for _, raw := range list {
		if m, ok := raw.(map[string]any); ok {
			out = append(out, normalizeJSONSchemaNode(m))
		}
	}
	return out
}

// mergeAllOf folds every allOf member into the node. All members must hold,
// and members disagreeing on a keyword cannot both be written into one
// schema, so the node's own keyword wins; that choice widens the constraint
// but never fails the schema. Properties merge by name, required lists union
// and enum lists intersect, which are exact for allOf semantics.
func mergeAllOf(node map[string]any, members []any) {
	for _, raw := range members {
		member, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		mergeSchemaInto(node, member)
	}
}

// mergeSchemaInto merges one normalized allOf member into dst.
func mergeSchemaInto(dst, member map[string]any) {
	for key, value := range member {
		switch key {
		case "properties":
			mergeProperties(dst, value)
		case "required":
			dst["required"] = unionRequired(dst["required"], value)
		case "enum":
			if existing, ok := dst["enum"]; ok {
				dst["enum"] = intersectEnums(existing, value)
				continue
			}
			dst[key] = value
		default:
			if _, exists := dst[key]; !exists {
				dst[key] = value
			}
		}
	}
}

// mergeProperties unions the member's properties into dst's, by name. Two
// different schemas for the same name become an anyOf choice: both must hold
// and one schema cannot say that, so the choice widens while keeping both
// types visible.
func mergeProperties(dst map[string]any, value any) {
	incoming, ok := value.(map[string]any)
	if !ok {
		return
	}
	existing, _ := dst["properties"].(map[string]any)
	if existing == nil {
		existing = map[string]any{}
	}
	for name, prop := range incoming {
		current, exists := existing[name]
		if !exists || reflect.DeepEqual(current, prop) {
			existing[name] = prop
			continue
		}
		existing[name] = map[string]any{"anyOf": []any{current, prop}}
	}
	dst["properties"] = existing
}

// unionRequired appends the member's required names that the node does not
// already list. Members are normalized but their required entries were not
// yet filtered to strings, so non-strings are skipped here.
func unionRequired(existing, value any) []any {
	out, _ := existing.([]any)
	seen := make(map[string]bool, len(out))
	for _, name := range out {
		if s, ok := name.(string); ok {
			seen[s] = true
		}
	}
	incoming, _ := value.([]any)
	for _, name := range incoming {
		s, ok := name.(string)
		if ok && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// intersectEnums keeps the values both enum lists contain, in the node's
// order. allOf requires both, so the intersection is exact. A non-list member
// enum leaves the node's list untouched.
func intersectEnums(existing, value any) any {
	left, _ := existing.([]any)
	right, ok := value.([]any)
	if !ok {
		return existing
	}
	out := make([]any, 0, len(left))
	for _, item := range left {
		for _, other := range right {
			if reflect.DeepEqual(item, other) {
				out = append(out, item)
				break
			}
		}
	}
	return out
}

// mergeOneOfIntoAnyOf appends oneOf branches to anyOf. The two differ only in
// that oneOf forbids matching more than one branch, which tool.Schema cannot
// express, so the merge widens the constraint instead of dropping the branch
// list the way field-by-field copying did.
func mergeOneOfIntoAnyOf(node map[string]any) {
	oneOf, ok := node["oneOf"].([]any)
	delete(node, "oneOf")
	if !ok {
		return
	}
	existing, _ := node["anyOf"].([]any)
	node["anyOf"] = append(existing, oneOf...)
}

// rewriteConst rewrites const as a one-value enum: the two are the same
// constraint. The type comes from the const value when the node has none, so
// a const-only node stays typed.
func rewriteConst(node map[string]any) {
	value, ok := node["const"]
	delete(node, "const")
	if !ok {
		return
	}
	if _, has := node["enum"]; !has {
		node["enum"] = []any{value}
	}
	if _, has := node["type"]; has {
		return
	}
	if t := jsonTypeOf(value); t != "" {
		node["type"] = t
	}
}

// jsonTypeOf returns the JSON Schema type of a decoded JSON value.
func jsonTypeOf(value any) string {
	switch value.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	case nil:
		return "null"
	}
	return ""
}

// rewriteTypeList rewrites a type list, such as ["string", "null"], as anyOf
// branches, one per type, appended after any existing anyOf branches. Members
// that are not type-name strings are ignored.
func rewriteTypeList(node map[string]any) {
	raw, ok := node["type"].([]any)
	if !ok {
		return
	}
	delete(node, "type")
	branches := make([]any, 0, len(raw))
	for _, item := range raw {
		name, ok := item.(string)
		if !ok {
			continue
		}
		branches = append(branches, map[string]any{"type": name})
	}
	if len(branches) == 0 {
		return
	}
	existing, _ := node["anyOf"].([]any)
	node["anyOf"] = append(existing, branches...)
}

// sanitizeKeywords drops keywords whose value shape would fail tool.Schema
// decoding, and filters required to its string entries. A schema with a
// malformed keyword keeps every other keyword instead of failing the whole
// conversion.
func sanitizeKeywords(node map[string]any) {
	for _, key := range []string{"type", "description", "pattern", "$ref"} {
		if value, exists := node[key]; exists {
			if _, ok := value.(string); !ok {
				delete(node, key)
			}
		}
	}
	if _, exists := node["enum"]; exists {
		if _, ok := node["enum"].([]any); !ok {
			delete(node, "enum")
		}
	}
	required, exists := node["required"]
	if !exists {
		return
	}
	list, ok := required.([]any)
	if !ok {
		delete(node, "required")
		return
	}
	names := make([]any, 0, len(list))
	for _, item := range list {
		if _, ok := item.(string); ok {
			names = append(names, item)
		}
	}
	node["required"] = names
}
