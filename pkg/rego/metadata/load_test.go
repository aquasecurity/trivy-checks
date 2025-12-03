package metadata_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

func TestLoadChecksMetadata(t *testing.T) {
	fs := fstest.MapFS{
		"check.rego": &fstest.MapFile{
			Data: []byte(`# METADATA
# title: Test title
# description: |
#   Description line 1
#   Description line 2
# related_resources:
#   - https://example.com/resource
# custom:
#   id: TEST-0001
#   aliases:
#     - test-alias
#   provider: aws
#   service: cloudwatch
#   severity: LOW
#   frameworks:
#     default:
#       - null
#     test-framework:
#       - "1.0"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudwatch
#             provider: aws
package builtin.aws.cloudwatch.test0001`),
			Mode: fs.ModePerm,
		},
	}

	metadataMap, err := metadata.LoadChecksMetadata(fs)
	require.NoError(t, err)
	require.Len(t, metadataMap, 1)

	meta, ok := metadataMap["check.rego"]
	require.True(t, ok)

	assert.Equal(t, "TEST-0001", meta.ID())
	assert.Equal(t, "LOW", meta.Severity())
	assert.False(t, meta.Deprecated())
	assert.Equal(t, metadata.Provider("aws"), meta.Provider())
	assert.Equal(t, "cloudwatch", meta.Service())

	assert.Equal(t, []string{"test-alias"}, meta.Aliases())

	assert.Equal(t, map[string][]string{
		"default":        nil,
		"test-framework": {"1.0"},
	}, meta.Frameworks())

	assert.True(t, meta.HasDefaultFramework())

	assert.Equal(t, "Test title", meta.Title)
	assert.Equal(t, "Description line 1\nDescription line 2\n", meta.Description)

	assert.Equal(t, []string{"https://example.com/resource"}, meta.Links)
}
