package rego

import (
	"encoding/json"
	"testing"

	opa "github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The unit tests call the implementations directly. This one goes through the OPA registry,
// so it also covers the declarations and the binding of each name to its implementation.
func TestRegisteredResultBuiltins(t *testing.T) {
	RegisterBuiltins()

	rs, err := opa.New(
		opa.Query(`[result.new("message", input).startline, isManaged(input)]`),
		opa.Input(map[string]any{
			"__defsec_metadata": map[string]any{
				"startline": 7,
				"managed":   false,
			},
		}),
	).Eval(t.Context())
	require.NoError(t, err)

	res, ok := opa.ResultValue[[]any](rs)
	require.True(t, ok)

	assert.Equal(t, []any{json.Number("7"), false}, res)
}
