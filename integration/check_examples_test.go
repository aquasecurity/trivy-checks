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
	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

var trivyVersions = []string{"0.57.1", "0.58.1", "latest", "canary"}

func TestScanCheckExamples(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "trivy-checks-examples-*")
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

			require.NoError(t, err)
			t.Cleanup(func() { trivy.Terminate(ctx) })

			rc, err := trivy.Logs(ctx)
			require.NoError(t, err)

			b, err := io.ReadAll(rc)
			require.NoError(t, err)

			// trivy switches to embedded checks if the bundle load fails, so we should check this out
			if bytes.Contains(b, []byte("Falling back to embedded checks")) {
				t.Log(string(b))
				t.Fatal("Failed to load checks from the bundle")
			}

			require.NoError(t, err)
			require.NoError(t, trivy.Terminate(ctx))

			reportPath := filepath.Join(targetDir, reportFileName)
			report := readTrivyReport(t, reportPath)
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

// TODO: skip checks based on the minimum_trivy_version field
// (minimum supported version of Trivy)
//
// TODO: AVD-AWS-0344 check is excluded because its input does not match the scheme of older versions of Trivy.
// Remove it for the latest version after this issue is resolved.
var excludedChecks = map[string][]string{
	// Excluded for all versions, as these checks are only for documentation and lack implementation.
	"": {
		"AVD-AWS-0057",
		"AVD-AWS-0114",
		"AVD-AWS-0120",
		"AVD-AWS-0134",
		"AVD-GCP-0075",
	},
	"0.57.1": {
		// After version 0.57.1, the bug with the field type was fixed and the example was updated. See: https://github.com/aquasecurity/trivy/pull/7995
		"AVD-AWS-0036",
		"AVD-AWS-0344",
		"AVD-GCP-0050",
	},
	"0.58.1": {
		"AVD-AWS-0344",
		"AVD-GCP-0050",
	},
	"latest": {
		"AVD-AWS-0344",
	},
}

func setupTarget(t *testing.T, targetDir string) {
	t.Helper()

	checksMetadata, err := metadata.LoadDefaultChecksMetadata()
	require.NoError(t, err)

	for _, meta := range checksMetadata {
		// TODO: scan all frameworks
		if !meta.HasDefaultFramework() {
			continue
		}

		if meta.Deprecated() {
			continue
		}

		examples, path, err := examples.GetCheckExamples(meta)
		require.NoError(t, err)

		if path == "" {
			continue
		}

		for provider, providerExamples := range examples {
			writeExamples(t, providerExamples.Bad.ToStrings(), provider, targetDir, meta.AVDID(), "bad")
			writeExamples(t, providerExamples.Good.ToStrings(), provider, targetDir, meta.AVDID(), "good")
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

func verifyReport(t *testing.T, results []Result, targetDir string, version string) {
	got := getFailureIDs(results)

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
