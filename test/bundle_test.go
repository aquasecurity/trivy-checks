package test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_BundleValidity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping on windows as it doesn't build a bundle on Windows anyway")
	}

	_ = os.RemoveAll("../bundle")
	_ = os.Remove("../bundle.tar.gz")
	defer func() {
		_ = os.RemoveAll("../bundle")
		_ = os.Remove("../bundle.tar.gz")
	}()

	cmd := exec.Command("cmd/bundle/bundle.sh")
	cmd.Env = append(os.Environ(), "GITHUB_REF=refs/tags/v1.2.3")
	cmd.Dir = ".."
	require.NoError(t, cmd.Run())

	archive, err := os.Open("../bundle.tar.gz")
	require.NoError(t, err)

	gz, err := gzip.NewReader(archive)
	require.NoError(t, err)

	tarReader := tar.NewReader(gz)

	fsys := make(fstest.MapFS)

	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)

		switch header.Typeflag {
		case tar.TypeDir:
		case tar.TypeReg:
			var buffer bytes.Buffer
			buffer.Grow(int(header.Size))
			_, err = io.Copy(&buffer, tarReader)
			require.NoError(t, err)
			fsys[filepath.Clean(header.Name)] = &fstest.MapFile{
				Data: buffer.Bytes(),
			}
		default:
			t.Fatalf("unknown type in %s: 0x%X", header.Name, header.Typeflag)
		}
	}

	policies, err := fsys.ReadDir("policies")
	require.NoError(t, err)

	entries, err := os.ReadDir("../checks")
	require.NoError(t, err)

	var expectedDirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			expectedDirs = append(expectedDirs, entry.Name())
		}
	}

	for _, expected := range expectedDirs {
		var found bool
		for _, policyDir := range policies {
			if policyDir.Name() == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "expected to find policy dir for %s", expected)
	}

}
