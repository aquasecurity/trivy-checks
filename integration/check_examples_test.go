//go:build integration

package integration

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/registry"

	"github.com/aquasecurity/trivy-checks/integration/testcontainer"
	"github.com/aquasecurity/trivy-checks/internal/examples"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/types"
)

var trivyVersions = []string{"0.57.1", "0.58.1", "latest", "canary"}

func TestScanCheckExamples(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp(".", "trivy-checks-examples-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	examplesPath := filepath.Join(tmpDir, "examples")
	setupTarget(t, examplesPath)

	targetDir, err := filepath.Abs(tmpDir)
	require.NoError(t, err)

	registryContainer, err := registry.Run(ctx, "registry:2")
	require.NoError(t, err)

	registryHost, err := registryContainer.HostAddress(ctx)
	require.NoError(t, err)

	bundleImage := registryHost + "/" + "trivy-checks:latest"

	bundlePath := buildBundle(t)
	pushBundle(t, ctx, bundlePath, bundleImage)

	for _, version := range trivyVersions {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			reportFileName := version + "_" + "report.json"
			args := []string{
				"conf",
				"--checks-bundle-repository", bundleImage,
				"--format", "json",
				"--output", "/testdata/" + reportFileName,
				"--include-deprecated-checks=false",
				"/testdata/examples",
			}

			trivy, err := testcontainer.RunTrivy(ctx, "aquasec/trivy:"+version, args,
				testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
					hc.NetworkMode = "host"
					hc.Mounts = []mount.Mount{
						{
							Type:   mount.TypeBind,
							Source: targetDir,
							Target: "/testdata",
						},
					}
				}),
			)

			rc, err := trivy.Logs(ctx)
			require.NoError(t, err)

			b, err := io.ReadAll(rc)
			require.NoError(t, err)

			if bytes.Contains(b, []byte("Falling back to embedded checks")) {
				t.Log(string(b))
				t.Fatal("Failed to load checks from the bundle")
			}

			require.NoError(t, err)
			require.NoError(t, trivy.Terminate(ctx))

			reportPath := filepath.Join(targetDir, reportFileName)
			report := readTrivyReport(t, reportPath)
			require.NotEmpty(t, report.Results)
			require.NoError(t, os.Remove(reportPath))

			verifyReport(t, report, examplesPath, version)
		})
	}
}

func buildBundle(t *testing.T) string {
	cmd := exec.Command("make", "create-bundle")
	cmd.Dir = ".."
	require.NoError(t, cmd.Run())
	t.Cleanup(func() { os.Remove("../bundle.tar.gz") })

	bundlePath, err := filepath.Abs("../bundle.tar.gz")
	require.NoError(t, err)
	return bundlePath
}

func pushBundle(t *testing.T, ctx context.Context, path string, image string) {
	orasCmd := []string{
		"push", image,
		"--artifact-type", "application/vnd.cncf.openpolicyagent.config.v1+json",
		filepath.Base(path) + ":application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
	}

	c, err := testcontainer.RunOras(ctx, orasCmd,
		testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
			config.NetworkMode = "host"
			config.Mounts = []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: path,
					Target: "/" + filepath.Base(path),
				}}
		}),
	)
	require.NoError(t, err)
	require.NoError(t, c.Terminate(ctx))
}

var excludedChecks = map[string][]string{
	// Excluded for all versions, as these checks are only for documentation and lack implementation.
	"": {
		"AVD-AWS-0057",
		"AVD-AWS-0114",
		"AVD-AWS-0120",
		"AVD-AWS-0134",
	},
	"0.57.1": {
		// After version 0.57.1, the bug with the field type was fixed and the example was updated. See: https://github.com/aquasecurity/trivy/pull/7995
		"AVD-AWS-0036",
	},
}

func setupTarget(t *testing.T, targetDir string) {
	t.Helper()

	// TODO(nikpivkin): load examples from fs
	rego.LoadAndRegister()

	for _, r := range rules.GetRegistered(framework.ALL) {
		if _, ok := r.Frameworks[framework.Default]; !ok {
			// TODO(nikpivkin): Trivy does not load non default checks
			continue
		}

		if r.Deprecated {
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
}

func writeExamples(t *testing.T, examples []string, provider, cacheDir string, id string, typ string) {
	for i, example := range examples {
		name := fileNameByProvider(provider)
		file := filepath.Join(cacheDir, id, provider, typ, strconv.Itoa(i), name)
		require.NoError(t, os.MkdirAll(filepath.Dir(file), fs.ModePerm))
		require.NoError(t, os.WriteFile(file, []byte(example), fs.ModePerm))
	}
}

func verifyReport(t *testing.T, report types.Report, targetDir string, version string) {
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

		if slices.Contains(excludedChecks[""], id) {
			return nil
		}

		if slices.Contains(excludedChecks[version], id) {
			return nil
		}

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

func fileNameByProvider(provider string) string {
	switch provider {
	case "terraform":
		return "main.tf"
	case "cloudformation":
		return "template.yaml"
	case "dockerfile":
		return "Dockerfile"
	case "kubernetes":
		return "test.yaml"
	}
	panic("unreachable: " + provider)
}
