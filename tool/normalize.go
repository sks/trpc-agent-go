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
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
)

// SchemaChangeKind names one rewrite NormalizeSchema made to a JSON Schema.
// Callers use it to log or count how their tools' schemas were adjusted
// without logging schema contents.
type SchemaChangeKind string

// The rewrites NormalizeSchema can make. Each keeps a tool schema valid for
// the Schema type instead of silently dropping keywords the type cannot hold.
const (
	// SchemaChangeOneOf means oneOf branches were appended to anyOf. The two
	// differ only in that oneOf forbids matching more than one branch, which
	// Schema cannot express, so the merge widens the constraint.
	SchemaChangeOneOf SchemaChangeKind = "one_of"
	// SchemaChangeConst means const became a one-value enum, with the type
	// taken from the value when the node had none.
	SchemaChangeConst SchemaChangeKind = "const"
	// SchemaChangeAllOfMerge means allOf members were merged into the node:
	// properties union by name, required lists union, enums intersect.
	SchemaChangeAllOfMerge SchemaChangeKind = "all_of_merge"
	// SchemaChangeAllOfConflict means a merged allOf member disagreed with the
	// node on a keyword and the node's own value was kept. Both had to hold, so
	// keeping one widens the constraint.
	SchemaChangeAllOfConflict SchemaChangeKind = "all_of_conflict"
	// SchemaChangeTuple means positional items (tuple items or prefixItems)
	// collapsed into one items schema whose anyOf accepts any position.
	SchemaChangeTuple SchemaChangeKind = "tuple"
	// SchemaChangeMalformed means a keyword whose value had the wrong JSON
	// shape, such as items: "x", was dropped so the rest of the schema still
	// converts.
	SchemaChangeMalformed SchemaChangeKind = "malformed"
	// SchemaChangeBoolean means a boolean schema value was rewritten: true
	// became the empty schema (any value), false was dropped because Schema
	// cannot express "no value allowed".
	SchemaChangeBoolean SchemaChangeKind = "boolean_schema"
	// SchemaChangeTypeList means a list of types, such as ["string", "null"],
	// became one anyOf branch per string member, with type-specific keywords
	// moved into their branch.
	SchemaChangeTypeList SchemaChangeKind = "type_list"
)

// SchemaChange records one rewrite NormalizeSchema made at a dotted schema
// path, such as "properties.params.items". An empty path is the root. Keys
// lists the keyword names the node had before the rewrite, so a caller's log
// line can show the original shape without logging schema values.
type SchemaChange struct {
	Path string
	Kind SchemaChangeKind
	Keys []string
}

// NormalizeSchema rewrites a decoded JSON Schema map into the keyword subset
// Schema can hold, returning the rewritten copy and the list of rewrites it
// made. Keywords Schema has no field for keep their values in the returned
// map, so a later JSON round trip drops them; the rewrites exist so keywords
// that ARE meaningful (oneOf, const, allOf, type lists, tuple items) survive
// conversion in the closest representable form instead of vanishing.
//
// The input is never modified: the returned map is a copy. A boolean true
// schema value becomes the empty schema (any value); false and malformed
// keyword values are dropped, which widens the constraint, and the server that
// produced the schema still validates every call. If the input cannot be
// JSON-encoded it is returned unchanged with no changes reported.
func NormalizeSchema(schema map[string]any) (map[string]any, []SchemaChange) {
	encoded, err := json.Marshal(schema)
	if err != nil {
		return schema, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return schema, nil
	}
	normalizer := &schemaNormalizer{}
	return normalizer.node(decoded, ""), normalizer.changes
}

// schemaNormalizer carries the change log of one NormalizeSchema run.
type schemaNormalizer struct {
	changes []SchemaChange
}

// record appends one change at path. original is the node as it looked before
// the rewrite; only its key names are kept, never values. It may be nil.
func (n *schemaNormalizer) record(path string, kind SchemaChangeKind, original map[string]any) {
	if last := len(n.changes) - 1; last >= 0 && n.changes[last].Path == path && n.changes[last].Kind == kind {
		return
	}
	change := SchemaChange{Path: path, Kind: kind}
	if original != nil {
		change.Keys = keyNames(original)
	}
	n.changes = append(n.changes, change)
}

// keyNames returns a node's keyword names in order.
func keyNames(node map[string]any) []string {
	keys := make([]string, 0, len(node))
	for key := range node {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// shallowCopy copies one map level, so a change record can keep the node's
// original keyword names while the rewrite mutates the node.
func shallowCopy(node map[string]any) map[string]any {
	out := make(map[string]any, len(node))
	for key, value := range node {
		out[key] = value
	}
	return out
}

// oneKeyword snapshots a node as "the one keyword that mattered", for change
// records whose rewrite removed that keyword before recording.
func oneKeyword(key string, value any) map[string]any {
	return map[string]any{key: value}
}

// node rewrites one decoded schema object. Children are normalized first, so
// allOf members arrive already rewritten and merging them needs no second pass.
func (n *schemaNormalizer) node(node map[string]any, path string) map[string]any {
	n.normalizeObjectMap(node, path, "properties")
	n.normalizeObjectMap(node, path, "$defs")
	n.normalizeItems(node, path)
	n.normalizeAdditionalProperties(node, path)
	n.normalizeBranchList(node, path, "anyOf")
	n.normalizeBranchList(node, path, "oneOf")
	var allOfSnapshot map[string]any
	if node["allOf"] != nil {
		allOfSnapshot = shallowCopy(node)
	}
	allOfMembers := n.takeObjectList(node, path, "allOf")
	if len(allOfMembers) > 0 {
		n.record(path, SchemaChangeAllOfMerge, allOfSnapshot)
	}
	n.mergeAllOf(node, path, allOfMembers)
	n.mergeOneOfIntoAnyOf(node, path)
	n.rewriteConst(node, path)
	n.rewriteTypeList(node, path)
	n.sanitizeKeywords(node, path)
	return node
}

// joinPath appends a segment to a dotted schema path.
func joinPath(path, segment string) string {
	if path == "" {
		return segment
	}
	return path + "." + segment
}

// normalizeObjectMap normalizes each object value of a name-to-schema keyword
// such as properties or $defs. A boolean true is the schema for any value and
// becomes the empty schema. False and non-schema values cannot be represented
// in Schema; dropping them widens what the input accepts, but keeps the rest
// of the schema instead of failing the whole conversion.
func (n *schemaNormalizer) normalizeObjectMap(node map[string]any, path, key string) {
	schemas, ok := node[key].(map[string]any)
	if !ok {
		if _, exists := node[key]; exists {
			original := node[key]
			delete(node, key)
			n.record(path, SchemaChangeMalformed, oneKeyword(key, original))
		}
		return
	}
	for name, raw := range schemas {
		childPath := joinPath(path, key+"."+name)
		switch v := raw.(type) {
		case map[string]any:
			schemas[name] = n.node(v, childPath)
		case bool:
			n.record(childPath, SchemaChangeBoolean, nil)
			if !v {
				delete(schemas, name)
				continue
			}
			schemas[name] = map[string]any{}
		default:
			delete(schemas, name)
			n.record(childPath, SchemaChangeMalformed, nil)
		}
	}
}

// normalizeItems rewrites the items keyword. Map form is normalized in place.
// Tuple form (items as a list) and prefixItems describe positions, which
// Schema cannot express, so the positions collapse into one items schema
// whose anyOf accepts any position; this widens the constraint but keeps
// every position's type visible to the model. Boolean or malformed items are
// dropped: true allows anything, and false (only the empty array) has no
// representable form.
func (n *schemaNormalizer) normalizeItems(node map[string]any, path string) {
	prefix := n.takeObjectList(node, path, "prefixItems")
	raw := node["items"]
	itemsPath := joinPath(path, "items")
	if len(prefix) == 0 {
		switch v := raw.(type) {
		case map[string]any:
			node["items"] = n.node(v, itemsPath)
		case []any:
			positions := n.normalizedObjects(v, itemsPath)
			if len(positions) == 0 {
				delete(node, "items")
				n.record(itemsPath, SchemaChangeMalformed, oneKeyword("items", raw))
				return
			}
			node["items"] = map[string]any{"anyOf": positions}
			n.record(itemsPath, SchemaChangeTuple, oneKeyword("items", raw))
		case bool:
			delete(node, "items")
			n.record(itemsPath, SchemaChangeBoolean, oneKeyword("items", raw))
		default:
			if raw != nil {
				delete(node, "items")
				n.record(itemsPath, SchemaChangeMalformed, oneKeyword("items", raw))
			}
		}
		return
	}
	positions := prefix
	switch v := raw.(type) {
	case map[string]any:
		positions = append(positions, n.node(v, itemsPath))
	case []any:
		positions = append(positions, n.normalizedObjects(v, itemsPath)...)
	}
	node["items"] = map[string]any{"anyOf": positions}
	n.record(itemsPath, SchemaChangeTuple, map[string]any{"items": raw, "prefixItems": prefix})
}

// normalizeAdditionalProperties keeps boolean values, normalizes the schema
// object form, and drops malformed values.
func (n *schemaNormalizer) normalizeAdditionalProperties(node map[string]any, path string) {
	switch v := node["additionalProperties"].(type) {
	case map[string]any:
		node["additionalProperties"] = n.node(v, joinPath(path, "additionalProperties"))
	case bool:
	default:
		if raw, exists := node["additionalProperties"]; exists {
			delete(node, "additionalProperties")
			n.record(joinPath(path, "additionalProperties"), SchemaChangeMalformed, oneKeyword("additionalProperties", raw))
		}
	}
}

// normalizeBranchList normalizes each object branch of an anyOf or oneOf
// keyword and drops branches that are not schema objects, including booleans,
// which Schema cannot represent.
func (n *schemaNormalizer) normalizeBranchList(node map[string]any, path, key string) {
	raw, ok := node[key].([]any)
	if !ok {
		if original, exists := node[key]; exists {
			delete(node, key)
			n.record(joinPath(path, key), SchemaChangeMalformed, oneKeyword(key, original))
		}
		return
	}
	branches := n.normalizedObjects(raw, joinPath(path, key))
	if len(branches) != len(raw) {
		n.record(joinPath(path, key), SchemaChangeBoolean, oneKeyword(key, raw))
	}
	if len(branches) == 0 {
		delete(node, key)
		return
	}
	node[key] = branches
}

// takeObjectList removes key from node and returns its object entries,
// normalized. A present but non-list value is malformed.
func (n *schemaNormalizer) takeObjectList(node map[string]any, path, key string) []any {
	raw, exists := node[key]
	delete(node, key)
	list, ok := raw.([]any)
	if !ok {
		if exists {
			n.record(joinPath(path, key), SchemaChangeMalformed, oneKeyword(key, raw))
		}
		return nil
	}
	return n.normalizedObjects(list, joinPath(path, key))
}

// normalizedObjects returns the schema-object entries of list, normalized.
func (n *schemaNormalizer) normalizedObjects(list []any, path string) []any {
	out := make([]any, 0, len(list))
	for i, raw := range list {
		if m, ok := raw.(map[string]any); ok {
			out = append(out, n.node(m, branchPath(path, i)))
		}
	}
	return out
}

// branchPath names one branch of a schema list keyword.
func branchPath(path string, i int) string {
	return path + "[" + strconv.Itoa(i) + "]"
}

// mergeAllOf folds every allOf member into the node. All members must hold,
// and members disagreeing on a keyword cannot both be written into one
// schema, so the node's own keyword wins; that choice widens the constraint
// but never fails the schema. Properties merge by name, required lists union
// and enum lists intersect, which are exact for allOf semantics.
func (n *schemaNormalizer) mergeAllOf(node map[string]any, path string, members []any) {
	for _, raw := range members {
		member, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		n.mergeSchemaInto(node, path, member)
	}
}

// mergeSchemaInto merges one normalized allOf member into dst.
func (n *schemaNormalizer) mergeSchemaInto(dst map[string]any, path string, member map[string]any) {
	for key, value := range member {
		switch key {
		case "properties":
			n.mergeProperties(dst, path, value)
		case "required":
			dst["required"] = unionRequired(dst["required"], value)
		case "enum":
			if existing, ok := dst["enum"]; ok {
				dst["enum"] = intersectEnums(existing, value)
				continue
			}
			dst[key] = value
		default:
			existing, exists := dst[key]
			if !exists {
				dst[key] = value
				continue
			}
			if !reflect.DeepEqual(existing, value) {
				n.record(path, SchemaChangeAllOfConflict, oneKeyword(key, existing))
			}
		}
	}
}

// mergeProperties unions the member's properties into dst's, by name. Two
// different schemas for the same name become an anyOf choice: both must hold
// and one schema cannot say that, so the choice widens while keeping both
// types visible.
func (n *schemaNormalizer) mergeProperties(dst map[string]any, path string, value any) {
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
		n.record(path, SchemaChangeAllOfConflict, nil)
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
// that oneOf forbids matching more than one branch, which Schema cannot
// express.
func (n *schemaNormalizer) mergeOneOfIntoAnyOf(node map[string]any, path string) {
	oneOf, ok := node["oneOf"].([]any)
	if !ok {
		return
	}
	original := shallowCopy(node)
	delete(node, "oneOf")
	existing, _ := node["anyOf"].([]any)
	node["anyOf"] = append(existing, oneOf...)
	n.record(path, SchemaChangeOneOf, original)
}

// rewriteConst rewrites const as a one-value enum: the two are the same
// constraint. The type comes from the const value when the node has none, so
// a const-only node stays typed.
func (n *schemaNormalizer) rewriteConst(node map[string]any, path string) {
	value, ok := node["const"]
	if !ok {
		return
	}
	original := shallowCopy(node)
	delete(node, "const")
	if _, has := node["enum"]; !has {
		node["enum"] = []any{value}
	}
	if _, has := node["type"]; !has {
		if t := jsonTypeOf(value); t != "" {
			node["type"] = t
		}
	}
	n.record(path, SchemaChangeConst, original)
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

// keywordsForSchemaType lists the keywords that constrain only one JSON type.
// They move into that type's branch when a type list is split, so a node
// mixing "array" and "string" does not leave items beside a string branch.
var keywordsForSchemaType = map[string][]string{
	"array":   {"items", "prefixItems", "minItems", "maxItems", "uniqueItems"},
	"object":  {"properties", "required", "additionalProperties", "minProperties", "maxProperties"},
	"string":  {"pattern", "format", "minLength", "maxLength"},
	"number":  {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"},
	"integer": {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"},
}

// rewriteTypeList rewrites a type list, such as ["string", "null"], as anyOf
// branches, one per type, appended after any existing anyOf branches. With
// several types, each branch receives the keywords that belong to its type;
// with a single type the node's keywords stay in place. Members that are not
// type-name strings are ignored.
func (n *schemaNormalizer) rewriteTypeList(node map[string]any, path string) {
	raw, ok := node["type"].([]any)
	if !ok {
		return
	}
	var names []string
	for _, item := range raw {
		if name, ok := item.(string); ok {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		delete(node, "type")
		n.record(path, SchemaChangeMalformed, oneKeyword("type", raw))
		return
	}
	original := shallowCopy(node)
	delete(node, "type")
	branches := make([]any, 0, len(names))
	for _, name := range names {
		branch := map[string]any{"type": name}
		if len(names) > 1 {
			for _, key := range keywordsForSchemaType[name] {
				if value, exists := node[key]; exists {
					branch[key] = value
					delete(node, key)
				}
			}
		}
		branches = append(branches, branch)
	}
	existing, _ := node["anyOf"].([]any)
	node["anyOf"] = append(existing, branches...)
	n.record(path, SchemaChangeTypeList, original)
}

// sanitizeKeywords drops keywords whose value shape would fail Schema
// decoding, and filters required to its string entries. A schema with a
// malformed keyword keeps every other keyword instead of failing the whole
// conversion.
func (n *schemaNormalizer) sanitizeKeywords(node map[string]any, path string) {
	for _, key := range []string{"type", "description", "pattern", "$ref"} {
		if value, exists := node[key]; exists {
			if _, ok := value.(string); !ok {
				delete(node, key)
				n.record(joinPath(path, key), SchemaChangeMalformed, oneKeyword(key, value))
			}
		}
	}
	if value, exists := node["enum"]; exists {
		if _, ok := value.([]any); !ok {
			delete(node, "enum")
			n.record(joinPath(path, "enum"), SchemaChangeMalformed, oneKeyword("enum", value))
		}
	}
	required, exists := node["required"]
	if !exists {
		return
	}
	list, ok := required.([]any)
	if !ok {
		delete(node, "required")
		n.record(joinPath(path, "required"), SchemaChangeMalformed, oneKeyword("required", required))
		return
	}
	names := make([]any, 0, len(list))
	for _, item := range list {
		if _, ok := item.(string); ok {
			names = append(names, item)
			continue
		}
		n.record(joinPath(path, "required"), SchemaChangeMalformed, oneKeyword("required", required))
	}
	node["required"] = names
}
