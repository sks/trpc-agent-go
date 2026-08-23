//
// Tencent is pleased to support the open source community by making trpc-agent-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-agent-go is licensed under the Apache License Version 2.0.
//

package engram

import (
	"fmt"
	"strings"
)

// FormatForContext formats retrieved records for injection into LLM context.
// Groups by type (Episodic / Semantic / Procedural) and returns a single string
// suitable for appending to a system or user message.
func FormatForContext(records []*Record) string {
	if len(records) == 0 {
		return ""
	}
	byType := make(map[MemoryType][]*Record)
	for _, r := range records {
		byType[r.Type] = append(byType[r.Type], r)
	}
	var b strings.Builder
	for _, t := range []MemoryType{TypeEpisodic, TypeSemantic, TypeProcedural} {
		list := byType[t]
		if len(list) == 0 {
			continue
		}
		label := typeLabel(t)
		b.WriteString(fmt.Sprintf("[%s]\n", label))
		for _, r := range list {
			if r.Title != "" {
				b.WriteString(fmt.Sprintf("- %s: %s\n", r.Title, r.Content))
			} else {
				b.WriteString(fmt.Sprintf("- %s\n", r.Content))
			}
		}
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}

func typeLabel(t MemoryType) string {
	switch t {
	case TypeEpisodic:
		return "Episodic"
	case TypeSemantic:
		return "Semantic"
	case TypeProcedural:
		return "Procedural"
	default:
		return string(t)
	}
}
