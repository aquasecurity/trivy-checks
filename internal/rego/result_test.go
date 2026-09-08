package rego

import (
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateResult(t *testing.T) {
	tests := []struct {
		name     string
		cause    string
		expected string
	}{
		{
			name:  "resource without metadata",
			cause: `{}`,
			expected: `{
	"msg": "message",
	"startline": 0,
	"endline": 0,
	"sourceprefix": "",
	"filepath": "",
	"explicit": false,
	"managed": true,
	"fskey": "",
	"resource": "",
	"parent": null
}`,
		},
		{
			name: "resource with metadata",
			cause: `{"__defsec_metadata": {
	"startline": 3,
	"endline": 5,
	"sourceprefix": "git",
	"filepath": "main.tf",
	"explicit": true,
	"managed": false,
	"fskey": "fs-key",
	"resource": "aws_s3_bucket.this"
}}`,
			expected: `{
	"msg": "message",
	"startline": 3,
	"endline": 5,
	"sourceprefix": "git",
	"filepath": "main.tf",
	"explicit": true,
	"managed": false,
	"fskey": "fs-key",
	"resource": "aws_s3_bucket.this",
	"parent": null
}`,
		},
		{
			name: "wrapped value keeps the metadata next to the value",
			cause: `{
	"value": false,
	"startline": 12,
	"endline": 14,
	"sourceprefix": "",
	"filepath": "main.tf",
	"explicit": false,
	"managed": true,
	"unresolvable": false,
	"fskey": "fs-key",
	"resource": "aws_s3_bucket.example"
}`,
			expected: `{
	"msg": "message",
	"startline": 12,
	"endline": 14,
	"sourceprefix": "",
	"filepath": "main.tf",
	"explicit": false,
	"managed": true,
	"fskey": "fs-key",
	"resource": "aws_s3_bucket.example",
	"parent": null
}`,
		},
		{
			name:  "dockerfile command keeps the location in its own fields",
			cause: `{"Path": "Dockerfile", "StartLine": 1, "EndLine": 2, "Cmd": "user"}`,
			expected: `{
	"msg": "message",
	"startline": 1,
	"endline": 2,
	"sourceprefix": "",
	"filepath": "Dockerfile",
	"explicit": false,
	"managed": true,
	"fskey": "",
	"resource": "",
	"parent": null
}`,
		},
		{
			name: "parent metadata is resolved recursively",
			cause: `{"__defsec_metadata": {
	"startline": 3,
	"filepath": "main.tf",
	"parent": {"startline": 1, "endline": 10, "filepath": "module.tf"}
}}`,
			expected: `{
	"msg": "message",
	"startline": 3,
	"endline": 0,
	"sourceprefix": "",
	"filepath": "main.tf",
	"explicit": false,
	"managed": true,
	"fskey": "",
	"resource": "",
	"parent": {
		"startline": 1,
		"endline": 10,
		"sourceprefix": "",
		"filepath": "module.tf",
		"explicit": false,
		"managed": true,
		"fskey": "",
		"resource": "",
		"parent": null
	}
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := createResult(rego.BuiltinContext{}, ast.StringTerm("message"), ast.MustParseTerm(tt.cause))
			require.NoError(t, err)

			expected := ast.MustParseTerm(tt.expected)
			assert.Zerof(t, ast.Compare(expected.Value, got.Value),
				"expected:\n%s\ngot:\n%s", expected, got)
		})
	}
}
func TestIsManaged(t *testing.T) {
	tests := []struct {
		name     string
		cause    string
		expected bool
	}{
		{
			name:     "managed by default",
			cause:    `{"__defsec_metadata": {"filepath": "main.tf"}}`,
			expected: true,
		},
		{
			name:     "unmanaged resource",
			cause:    `{"__defsec_metadata": {"managed": false}}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsManagedImpl(rego.BuiltinContext{}, ast.MustParseTerm(tt.cause))
			require.NoError(t, err)
			assert.Equal(t, ast.Boolean(tt.expected), got.Value)
		})
	}
}
