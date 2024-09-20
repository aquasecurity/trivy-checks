package test

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/dockerfile"
	"github.com/liamg/memoryfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	builtinrego "github.com/aquasecurity/trivy-checks/pkg/rego"
)

func init() {
	builtinrego.RegisterBuiltins()
}

func getFileName(fpath string, info os.FileInfo, typePolicy bool) string {
	pathParts := strings.Split(fpath, filepath.FromSlash("/"))
	fileName := info.Name()
	// append test data folder to input file name example Dockerfile.allowed_DS001
	if len(pathParts) > 2 && !typePolicy {
		fileName = fmt.Sprintf("%s_%s", fileName, pathParts[len(pathParts)-2])
	}
	return fileName
}

func addFilesToMemFS(memfs *memoryfs.FS, typePolicy bool, folderName string) error {
	base := filepath.Base(folderName)
	if err := memfs.MkdirAll(base, 0o700); err != nil {
		return err
	}
	err := filepath.Walk(filepath.FromSlash(folderName),
		func(fpath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			if typePolicy && !rego.IsRegoFile(info.Name()) {
				return nil
			}
			data, err := os.ReadFile(fpath)
			if err != nil {
				return err
			}
			fileName := getFileName(fpath, info, typePolicy)
			if err := memfs.WriteFile(path.Join(base, fileName), data, 0o644); err != nil {
				return err
			}
			return nil
		})

	if err != nil {
		return err
	}
	return nil
}

func Test_Docker_RegoPoliciesFromDisk(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("./testdata/dockerfile")
	require.NoError(t, err)

	policiesPath, err := filepath.Abs("../checks/docker")
	require.NoError(t, err)
	scanner := dockerfile.NewScanner(
		rego.WithPolicyDirs(filepath.Base(policiesPath)),
		rego.WithEmbeddedLibraries(true),
	)
	memfs := memoryfs.New()
	// add policies
	err = addFilesToMemFS(memfs, true, policiesPath)
	require.NoError(t, err)

	// add test data
	testDataPath, err := filepath.Abs("./testdata/dockerfile")
	require.NoError(t, err)
	err = addFilesToMemFS(memfs, false, testDataPath)
	require.NoError(t, err)

	results, err := scanner.ScanFS(context.TODO(), memfs, filepath.Base(testDataPath))
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			require.NoError(t, err)
			t.Run(entry.Name(), func(t *testing.T) {
				var matched int
				for _, result := range results {
					if result.Rule().HasID(entry.Name()) && result.Status() == scan.StatusFailed {
						if result.Description() != "Specify at least 1 USER command in Dockerfile with non-root user as argument" {
							assert.Greater(t, result.Range().GetStartLine(), 0)
							assert.Greater(t, result.Range().GetEndLine(), 0)
						}
						if !strings.HasSuffix(result.Range().GetFilename(), entry.Name()) {
							continue
						}
						matched++
					}
				}
				assert.Equal(t, 1, matched, "Rule should be matched once")
			})

		})
	}
}

func Test_Docker_RegoPoliciesEmbedded(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("./testdata/dockerfile")
	require.NoError(t, err)

	scanner := dockerfile.NewScanner(rego.WithEmbeddedPolicies(true), rego.WithEmbeddedLibraries(true))
	srcFS := os.DirFS("../")

	results, err := scanner.ScanFS(context.TODO(), srcFS, "test/testdata/dockerfile")
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			require.NoError(t, err)
			t.Run(entry.Name(), func(t *testing.T) {
				var matched bool
				for _, result := range results {
					if result.Rule().HasID(entry.Name()) && result.Status() == scan.StatusFailed {
						if result.Description() != "Specify at least 1 USER command in Dockerfile with non-root user as argument" {
							assert.Greater(t, result.Range().GetStartLine(), 0)
							assert.Greater(t, result.Range().GetEndLine(), 0)
						}
						assert.Equal(t, fmt.Sprintf("test/testdata/dockerfile/%s/Dockerfile.denied", entry.Name()), result.Range().GetFilename())
						matched = true
					}
				}
				assert.True(t, matched)
			})

		})
	}
}
