package rego

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseResult(t *testing.T) {
	tests := []struct {
		name     string
		raw      any
		expected Result
	}{
		{
			name:     "message only",
			raw:      "something is wrong",
			expected: Result{Message: "something is wrong", Managed: true},
		},
		{
			name: "result object",
			raw: map[string]any{
				"msg":       "something is wrong",
				"startline": json.Number("7"),
				"filepath":  "main.tf",
			},
			expected: Result{
				Message:   "something is wrong",
				Filepath:  "main.tf",
				StartLine: 7,
				Managed:   true,
			},
		},
		{
			name: "message next to a result object",
			raw: []any{
				"something is wrong",
				map[string]any{"filepath": "main.tf"},
			},
			expected: Result{
				Message:  "something is wrong",
				Filepath: "main.tf",
				Managed:  true,
			},
		},
		{
			name:     "nothing to read",
			raw:      true,
			expected: Result{Message: "Rego check resulted in DENY", Managed: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseResult(tt.raw))
		})
	}
}
