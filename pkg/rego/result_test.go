package rego

import (
	"slices"
	"testing"

	opa "github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The check builds the result with result.new and this package reads it back, so the
// test goes through OPA to cover both halves of the contract at once.
func TestParseResults(t *testing.T) {
	RegisterBuiltins()

	const module = `package test

import rego.v1

deny contains res if {
	res := result.new("message", input)
}
`

	rs, err := opa.New(
		opa.Query("data.test.deny"),
		opa.Module("test.rego", module),
		opa.Input(map[string]any{
			"__defsec_metadata": map[string]any{
				"startline":    3,
				"endline":      5,
				"sourceprefix": "git",
				"filepath":     "main.tf",
				"explicit":     true,
				"managed":      false,
				"fskey":        "fs-key",
				"resource":     "aws_s3_bucket.this",
				"parent": map[string]any{
					"startline": 1,
					"endline":   10,
					"filepath":  "module.tf",
				},
			},
		}),
	).Eval(t.Context())
	require.NoError(t, err)

	expected := []Result{
		{
			Message:      "message",
			Filepath:     "main.tf",
			Resource:     "aws_s3_bucket.this",
			StartLine:    3,
			EndLine:      5,
			SourcePrefix: "git",
			Explicit:     true,
			Managed:      false,
			FSKey:        "fs-key",
			Parent: &Result{
				Filepath:  "module.tf",
				StartLine: 1,
				EndLine:   10,
				Managed:   true,
			},
		},
	}

	assert.Equal(t, expected, slices.Collect(ParseResults(rs)))
}
