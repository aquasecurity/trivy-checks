//go:build integration

package integration

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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

	// TODO(nikpivkin): load examples from fs
	rego.LoadAndRegister()

	for _, r := range rules.GetRegistered(framework.ALL) {
		if _, ok := r.Frameworks[framework.Default]; !ok {
			// TODO(nikpivkin): Trivy does not load non default checks
			continue
		}

		t.Run(r.AVDID, func(t *testing.T) {
			examples, path, err := examples.GetCheckExamples(r.Rule)
			require.NoError(t, err)

			if path == "" {
				return
			}

			for provider, providerExamples := range examples {
				validateExamples(t, providerExamples.Bad.ToStrings(), provider, cacheDir, r.AVDID, true)
				validateExamples(t, providerExamples.Good.ToStrings(), provider, cacheDir, r.AVDID, false)
			}
		})
	}
}

func validateExamples(t *testing.T, examples []string, provider, cacheDir, avdID string, expected bool) {
	for i, example := range examples {
		fileName := fmt.Sprintf("test-%d%s", i, extensionByProvider(provider))
		t.Run(fileName, func(t *testing.T) {
			targetFile := filepath.Join(t.TempDir(), fileName)

			require.NoError(t, os.WriteFile(targetFile, []byte(example), fs.ModePerm))

			outputFile := filepath.Join(t.TempDir(), "report.json")

			args := []string{
				"conf",
				"--skip-check-update",
				"--quiet",
				"--format", "json",
				"--output", outputFile,
				"--cache-dir", cacheDir,
				targetFile,
			}
			runTrivy(t, args)

			report := readTrivyReport(t, outputFile)

			assert.Equal(t, expected, reportContainsMisconfig(report, fileName, avdID))
		})
	}
}

func setupCache(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("make", "create-bundle")
	cmd.Dir = ".."

	require.NoError(t, cmd.Run())
	defer os.Remove("bundle.tar.gz")

	cacheDir := t.TempDir()

	policyDir := filepath.Join(cacheDir, "policy", "content")
	require.NoError(t, os.MkdirAll(policyDir, os.ModePerm))

	cmd = exec.Command("tar", "-zxf", "bundle.tar.gz", "-C", policyDir)
	cmd.Dir = ".."
	require.NoError(t, cmd.Run())

	return cacheDir
}

func reportContainsMisconfig(report types.Report, path string, id string) bool {
	for _, res := range report.Results {
		if res.Target != path {
			continue
		}

		for _, misconf := range res.Misconfigurations {
			if misconf.AVDID == id && misconf.Status == types.MisconfStatusFailure {
				return true
			}
		}
	}

	return false
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
