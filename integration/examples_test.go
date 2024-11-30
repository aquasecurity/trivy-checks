package test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestExamples(t *testing.T) {
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
			t.Cleanup(viper.Reset)

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

			out, err := os.ReadFile(outputFile)
			require.NoError(t, err)

			var rep types.Report
			require.NoError(t, json.Unmarshal(out, &rep))

			defer func() {
				if t.Failed() {
					t.Log(string(out))
				}
			}()

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

func runTrivy(t *testing.T, args []string) {
	t.Helper()

	app := commands.NewApp()
	app.SetOut(io.Discard)
	app.SetArgs(args)

	err := app.ExecuteContext(context.TODO())
	require.NoError(t, err)
}
