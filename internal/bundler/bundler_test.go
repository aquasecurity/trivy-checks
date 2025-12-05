package bundler_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"
	"testing/fstest"

	"github.com/aquasecurity/trivy-checks/internal/bundler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundlerBuild(t *testing.T) {
	fsys := fstest.MapFS{
		"checks/kubernetes/policy.rego":      &fstest.MapFile{Data: []byte("package kubernetes")},
		"checks/kubernetes/policy.yaml":      &fstest.MapFile{Data: []byte("should be filtered out")},
		"checks/kubernetes/policy_test.rego": &fstest.MapFile{Data: []byte("should be filtered out")},
		"checks/docker/policy.rego":          &fstest.MapFile{Data: []byte("package docker")},
		"checks/cloud/check.go":              &fstest.MapFile{Data: []byte("should be filtered out")},
		"checks/cloud/policy.rego":           &fstest.MapFile{Data: []byte("package cloud")},
		"lib/docker/libfile.rego":            &fstest.MapFile{Data: []byte("lib content")},
		"lib/kubernetes/libfile.rego":        &fstest.MapFile{Data: []byte("lib content")},
		"lib/cloud/libfile.rego":             &fstest.MapFile{Data: []byte("lib content")},
		"lib/test/libfile.rego":              &fstest.MapFile{Data: []byte("lib content")},
		"commands/kubernetes/test.yaml":      &fstest.MapFile{Data: []byte("command")},
		"commands/config/test.yaml":          &fstest.MapFile{Data: []byte("command")},
		"pkg/compliance/test.yaml":           &fstest.MapFile{Data: []byte("compliance")},
		"pkg/compliance/README.md":           &fstest.MapFile{Data: []byte("should be filtered out")},
	}

	b := bundler.New(".", fsys)

	var buf bytes.Buffer
	require.NoError(t, b.Build(&buf))
	require.NotEmpty(t, buf.Len())

	gr, err := gzip.NewReader(&buf)
	require.NoError(t, err)
	defer gr.Close()

	tr := tar.NewReader(gr)

	foundFiles := make(map[string]bool)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		foundFiles[hdr.Name] = true
	}

	t.Log(foundFiles)

	expectedFiles := []string{
		"policies/kubernetes/policies/policy.rego",
		"policies/kubernetes/lib/libfile.rego",
		"policies/docker/policies/policy.rego",
		"policies/docker/lib/libfile.rego",
		"policies/cloud/policies/policy.rego",
		"policies/cloud/lib/libfile.rego",
		"policies/test/lib/libfile.rego",
		"commands/config/test.yaml",
		"commands/kubernetes/test.yaml",
		"specs/compliance/test.yaml",
	}

	assert.Len(t, foundFiles, len(expectedFiles))

	for _, f := range expectedFiles {
		if !foundFiles[f] {
			t.Errorf("Expected file %q in archive, but not found", f)
		}
	}

	notExpectedFiles := []string{
		"policies/kubernetes/policies/policy.yaml",
		"policies/kubernetes/policies/policy_test.rego",
		"policies/cloud/policies/check.go",
		"specs/compliance/README.MD",
	}
	for _, f := range notExpectedFiles {
		if foundFiles[f] {
			t.Errorf("File %q should be filtered out but found in archive", f)
		}
	}

	assert.Equal(t, len(fsys), len(expectedFiles)+len(notExpectedFiles))
}
