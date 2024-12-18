//go:build integration

package integration

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-checks/internal/examples"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestValidateCheckExamples(t *testing.T) {
	cacheDir := setupCache(t)
	targetDir := setupTarget(t)
	outputFile := filepath.Join(t.TempDir(), "report.json")

	args := []string{
		"conf",
		"--skip-check-update",
		"--quiet",
		"--format", "json",
		"--output", outputFile,
		"--cache-dir", cacheDir,
		targetDir,
	}
	runTrivy(t, args)

	report := readTrivyReport(t, outputFile)

	verifyExamples(t, report, targetDir)
}

func setupCache(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("make", "create-bundle")
	cmd.Dir = ".."
	require.NoError(t, cmd.Run())
	defer os.Remove("../bundle.tar.gz")

	cacheDir := t.TempDir()

	policyDir := filepath.Join(cacheDir, "policy", "content")
	require.NoError(t, os.MkdirAll(policyDir, os.ModePerm))

	cmd = exec.Command("tar", "-zxf", "bundle.tar.gz", "-C", policyDir)
	cmd.Dir = ".."
	require.NoError(t, cmd.Run())

	return cacheDir
}

// Rego checks without implementation for documentation only.
var excludedChecks = []string{
	"AVD-AWS-0057",
	"AVD-AWS-0114",
	"AVD-AWS-0120",
	"AVD-AWS-0134",
}

func setupTarget(t *testing.T) string {
	t.Helper()

	targetDir := t.TempDir()

	// TODO(nikpivkin): load examples from fs
	rego.LoadAndRegister()

	for _, r := range rules.GetRegistered(framework.ALL) {
		if _, ok := r.Frameworks[framework.Default]; !ok {
			// TODO(nikpivkin): Trivy does not load non default checks
			continue
		}

		if slices.Contains(excludedChecks, r.AVDID) {
			continue
		}

		examples, path, err := examples.GetCheckExamples(r.Rule)
		require.NoError(t, err)

		if path == "" {
			continue
		}

		for provider, providerExamples := range examples {
			writeExamples(t, providerExamples.Bad.ToStrings(), provider, targetDir, r.AVDID, "bad")
			writeExamples(t, providerExamples.Good.ToStrings(), provider, targetDir, r.AVDID, "good")
		}
	}

	return targetDir
}

func writeExamples(t *testing.T, examples []string, provider, cacheDir string, id string, typ string) {
	for i, example := range examples {
		name := "test" + extensionByProvider(provider)
		file := filepath.Join(cacheDir, id, provider, typ, strconv.Itoa(i), name)
		require.NoError(t, os.MkdirAll(filepath.Dir(file), fs.ModePerm))
		require.NoError(t, os.WriteFile(file, []byte(example), fs.ModePerm))
	}
}

func verifyExamples(t *testing.T, report types.Report, targetDir string) {
	got := getFailureIDs(report)

	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(targetDir, path)
		require.NoError(t, err)

		parts := strings.Split(relPath, string(os.PathSeparator))
		require.Len(t, parts, 5)

		id, _, exampleType := parts[0], parts[1], parts[2]

		shouldBePresent := exampleType == "bad"

		t.Run(relPath, func(t *testing.T) {
			if shouldBePresent {
				ids, exists := got[relPath]
				assert.True(t, exists)
				assert.Contains(t, ids, id)
			} else {
				ids, exists := got[relPath]
				if exists {
					assert.NotContains(t, ids, id)
				}
			}
		})
		return nil
	})

	require.NoError(t, err)
}

func getFailureIDs(report types.Report) map[string][]string {
	ids := make(map[string][]string)

	for _, result := range report.Results {
		for _, misconf := range result.Misconfigurations {
			if misconf.Status == types.MisconfStatusFailure {
				ids[result.Target] = append(ids[result.Target], misconf.AVDID)
			}
		}
	}

	return ids
}

func extensionByProvider(provider string) string {
	switch provider {
	case "terraform":
		return ".tf"
	case "cloudformation":
		return ".yaml"
	}
	panic("unreachable")
}
