//go:build integration

package integration

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestCustomChecks(t *testing.T) {
	workDir, err := filepath.Abs("../examples")
	require.NoError(t, err)

	tests := []struct {
		dir        string
		args       []string
		expectedID string
	}{
		{
			dir: "cloudformation",
			args: []string{
				"--config-data", filepath.Join(workDir, "cloudformation", "data"),
				"--misconfig-scanners", "json",
			},
			expectedID: "USR-CF-0001",
		},
		{
			dir: "docker-compose",
			args: []string{
				"--misconfig-scanners", "yaml",
			},
			expectedID: "USR-COMPOSE-0001",
		},
		{
			dir: "dockerfile",
			args: []string{
				"--misconfig-scanners", "dockerfile",
			},
			expectedID: "USR-DF-0001",
		},
		{
			dir: "kubernetes",
			args: []string{
				"--misconfig-scanners", "kubernetes",
			},
			expectedID: "USR-KUBE-0001",
		},
		{
			dir: "serverless",
			args: []string{
				"--misconfig-scanners", "yaml",
			},
			expectedID: "USR-SERVERLESS-0001",
		},
		{
			dir: "terraform",
			args: []string{
				"--misconfig-scanners", "terraform",
			},
			expectedID: "USR-TF-0001",
		},
		{
			dir: "terraform-plan",
			args: []string{
				"--misconfig-scanners", "json",
			},
			expectedID: "USR-TFPLAN-0001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			targetDir := filepath.Join(workDir, tt.dir)
			outputFile := filepath.Join(t.TempDir(), "report.json")

			args := []string{
				"--format", "json",
				"--output", outputFile,
				"--quiet",
				"--config-check", targetDir,
				"--check-namespaces", "user",
				"--skip-check-update",
				"--ignore-policy", filepath.Join(workDir, "ignore.rego"),
			}

			args = append(args, tt.args...)

			trivyArgs := []string{"conf", targetDir}
			trivyArgs = append(trivyArgs, args...)
			runTrivy(t, trivyArgs)

			rep := readTrivyReport(t, outputFile)

			results := filterResults(rep.Results)

			require.Len(t, results, 1)
			fails := collectFailures(results[0].Misconfigurations)

			require.Len(t, fails, 1)
			assert.Equal(t, tt.expectedID, fails[0].AVDID)

		})
	}
}

func filterResults(results types.Results) types.Results {
	var ret types.Results
	for _, res := range results {
		if res.Target != "." {
			ret = append(ret, res)
		}
	}
	return ret
}

func collectFailures(misconfs []types.DetectedMisconfiguration) []types.DetectedMisconfiguration {
	var fails []types.DetectedMisconfiguration
	for _, misconf := range misconfs {
		if misconf.Status == types.MisconfStatusFailure {
			fails = append(fails, misconf)
		}
	}
	return fails
}
