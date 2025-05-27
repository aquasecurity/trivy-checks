//go:build integration

package integration

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/aquasecurity/trivy-checks/integration/testcontainer"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestCustomChecks(t *testing.T) {

	tests := []struct {
		dir        string
		args       []string
		expectedID string
	}{
		{
			dir: "cloudformation",
			args: []string{
				"--config-data", "data",
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
			outputFile := "report.json"

			args := []string{
				"conf",
				".",
				"--format", "json",
				"--output", outputFile,
				"--quiet",
				"--config-check", ".",
				"--check-namespaces", "user",
				"--skip-check-update",
				"--ignore-policy", "../ignore.rego",
			}

			args = append(args, tt.args...)

			examplesPath, err := filepath.Abs("../examples")
			require.NoError(t, err)

			reportPath := filepath.Join(examplesPath, tt.dir, outputFile)

			trivy, err := testcontainer.RunTrivy(t.Context(), "aquasec/trivy:latest", args,
				testcontainers.WithConfigModifier(func(config *container.Config) {
					config.WorkingDir = "/testdata/" + tt.dir
				}),
				testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
					hc.NetworkMode = "host"
					hc.Mounts = []mount.Mount{
						{
							Type:   mount.TypeBind,
							Source: examplesPath,
							Target: "/testdata",
						},
					}
				}),
			)
			require.NoError(t, err)
			t.Cleanup(func() {
				trivy.Terminate(t.Context())
				os.Remove(reportPath)
			})

			state, err := trivy.State(t.Context())
			require.NoError(t, err)

			if state.ExitCode != 0 {
				rc, err := trivy.Logs(t.Context())
				require.NoError(t, err)

				b, err := io.ReadAll(rc)
				require.NoError(t, err)
				t.Fatal(string(b))
			}

			rep := readTrivyReport(t, reportPath)

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
