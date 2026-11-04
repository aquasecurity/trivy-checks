package rego

import (
	"encoding/json"
	"iter"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Result is a finding reported by a check, built by the result.new built-in.
type Result struct {
	Message      string
	Filepath     string
	Resource     string
	StartLine    int
	EndLine      int
	SourcePrefix string
	Explicit     bool
	Managed      bool
	FSKey        string
	Parent       *Result
}

// ParseResults reads back the findings the checks reported. A rule that builds a set
// gives all of its findings in one expression, a complete rule gives a single one.
func ParseResults(rs rego.ResultSet) iter.Seq[Result] {
	return func(yield func(Result) bool) {
		for _, result := range rs {
			for _, expression := range result.Expressions {
				values, ok := expression.Value.([]any)
				if !ok {
					values = []any{expression.Value}
				}

				for _, value := range values {
					if !yield(parseResult(value)) {
						return
					}
				}
			}
		}
	}
}

// The checks here always report the result.new object. A plain message, or a message
// next to the object, is read for backward compatibility.
func parseResult(raw any) Result {
	var result Result
	result.Managed = true
	switch val := raw.(type) {
	case []any:
		var msg string
		for _, item := range val {
			switch raw := item.(type) {
			case map[string]any:
				result = parseCause(raw)
			case string:
				msg = raw
			}
		}
		result.Message = msg
	case string:
		result.Message = val
	case map[string]any:
		result = parseCause(val)
	default:
		result.Message = "Rego check resulted in DENY"
	}
	return result
}

func parseCause(cause map[string]any) Result {
	var result Result
	result.Managed = true
	if msg, ok := cause[resultKeyMessage]; ok {
		result.Message = parseString(msg)
	}
	if filepath, ok := cause[resultKeyFilepath]; ok {
		result.Filepath = parseString(filepath)
	}
	if fskey, ok := cause[resultKeyFSKey]; ok {
		result.FSKey = parseString(fskey)
	}
	if resource, ok := cause[resultKeyResource]; ok {
		result.Resource = parseString(resource)
	}
	if start, ok := cause[resultKeyStartLine]; ok {
		result.StartLine = parseLineNumber(start)
	}
	if end, ok := cause[resultKeyEndLine]; ok {
		result.EndLine = parseLineNumber(end)
	}
	if prefix, ok := cause[resultKeySourcePrefix]; ok {
		result.SourcePrefix = parseString(prefix)
	}
	if explicit, ok := cause[resultKeyExplicit]; ok {
		if set, ok := explicit.(bool); ok {
			result.Explicit = set
		}
	}
	if managed, ok := cause[resultKeyManaged]; ok {
		if set, ok := managed.(bool); ok {
			result.Managed = set
		}
	}
	if parent, ok := cause[resultKeyParent]; ok {
		if m, ok := parent.(map[string]any); ok {
			parentResult := parseCause(m)
			result.Parent = &parentResult
		}
	}
	return result
}

func parseString(raw any) string {
	s, _ := raw.(string)
	return s
}

// OPA keeps the text of a number instead of turning it into a float, so that large
// integers survive the conversion.
func parseLineNumber(raw any) int {
	num, ok := raw.(json.Number)
	if !ok {
		return 0
	}
	n, _ := num.Int64()
	return int(n)
}
