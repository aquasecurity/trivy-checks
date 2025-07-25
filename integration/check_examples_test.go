//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/registry"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy-checks/integration/testcontainer"
	"github.com/aquasecurity/trivy-checks/internal/examples"
	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

var trivyVersions = []string{"0.57.1", "0.58.1", "latest", "canary"}

func TestScanCheckExamples(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp(".", "trivy-checks-examples-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	examplesPath := filepath.Join(tmpDir, "examples")
	checksMetadata := setupTarget(t, examplesPath)

	targetDir, err := filepath.Abs(tmpDir)
	require.NoError(t, err)

	registryContainer, err := registry.Run(ctx, "registry:2")
	require.NoError(t, err)
	t.Cleanup(func() { registryContainer.Terminate(context.TODO()) })

	registryHost, err := registryContainer.HostAddress(ctx)
	require.NoError(t, err)

	bundleImage := registryHost + "/" + "trivy-checks:latest"

	bundlePath := buildBundle(t)
	pushBundle(t, ctx, bundlePath, bundleImage)

	for _, version := range trivyVersions {
		t.Run(version, func(t *testing.T) {
			reportFileName := version + "_" + "report.json"

			trivyVer := getActualTrivyVersion(t, version)

			args := []string{
				"conf",
				"--checks-bundle-repository", bundleImage,
				"--format", "json",
				"--output", "/testdata/" + reportFileName,
				"--include-deprecated-checks=false",
				"/testdata/examples",
			}
			trivy, err := testcontainer.RunTrivy(ctx, "aquasec/trivy:"+version, args,
				testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
					ContainerRequest: testcontainers.ContainerRequest{
						AlwaysPullImage: false,
					},
				}),
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

			verifyReport(t, report, examplesPath, trivyVer, checksMetadata)
		})
	}
}

func getActualTrivyVersion(t *testing.T, version string) semver.Version {
	t.Helper()

	args := []string{
		"version",
		"-f", "json",
		"-q",
	}

	trivy, err := testcontainer.RunTrivy(t.Context(), "aquasec/trivy:"+version, args,
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				WaitingFor: wait.ForExit(),
			},
		}),
	)
	defer trivy.Terminate(t.Context())

	rc, err := trivy.Logs(t.Context())
	require.NoError(t, err)

	b, err := io.ReadAll(rc)
	require.NoError(t, err)

	t.Logf("Version response: %q", string(b))
	require.NoError(t, err)

	var resp struct {
		Version string `json:"Version"`
	}
	require.NoError(t, json.Unmarshal(b, &resp))
	require.NotEmpty(t, resp.Version)

	ver, err := semver.Parse(resp.Version)
	require.NoError(t, err)
	t.Logf("Actual Trivy version is %s", ver.String())
	return ver
}

func buildBundle(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("make", "create-bundle")
	cmd.Dir = ".."
	require.NoError(t, cmd.Run())
	t.Cleanup(func() { os.Remove("../bundle.tar.gz") })

	bundlePath, err := filepath.Abs("../bundle.tar.gz")
	require.NoError(t, err)
	return bundlePath
}

func pushBundle(t *testing.T, ctx context.Context, path string, image string) {
	t.Helper()

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

func setupTarget(t *testing.T, targetDir string) map[string]metadata.Metadata {
	t.Helper()

	checksMetadata, err := metadata.LoadDefaultChecksMetadata()
	require.NoError(t, err)

	metadataByID := make(map[string]metadata.Metadata)

	for _, meta := range checksMetadata {
		// TODO: scan all frameworks
		if !meta.HasDefaultFramework() {
			continue
		}

		if meta.Deprecated() {
			continue
		}

		checkExamples, path, err := examples.GetCheckExamples(meta)
		require.NoError(t, err)

		if path == "" {
			t.Logf("Skip check %s without examples", meta.ID())
			continue
		}

		metadataByID[meta.ID()] = meta

		for provider, providerExamples := range checkExamples {
			writeExamples(t, providerExamples.Bad.ToStrings(), provider, targetDir, meta.ID(), "bad")
			writeExamples(t, providerExamples.Good.ToStrings(), provider, targetDir, meta.ID(), "good")
		}
	}
	return metadataByID
}

func writeExamples(t *testing.T, examples []string, provider, cacheDir string, id string, typ string) {
	for i, example := range examples {
		name := fileNameByProvider(provider)
		file := filepath.Join(cacheDir, id, provider, typ, strconv.Itoa(i), name)
		require.NoError(t, os.MkdirAll(filepath.Dir(file), fs.ModePerm))
		require.NoError(t, os.WriteFile(file, []byte(example), fs.ModePerm))
	}
}

func verifyReport(
	t *testing.T, results []Result, targetDir string, trivyVer semver.Version,
	checksMetadata map[string]metadata.Metadata,
) {
	t.Helper()

	got := getFailureIDs(results)

	minVersions := make(map[string]semver.Version)

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

		// Trivy filters the checks by the minimum supported version itself,
		// but this feature appeared after some of the checks had already been updated,
		// so here we re-apply filtering for compatibility.
		if shouldSkipCheck(t, id, checksMetadata, minVersions, trivyVer) {
			t.Logf("Skip unsupported check %s for %s", id, trivyVer.String())
			return filepath.SkipDir
		}

		meta := checksMetadata[id]
		shouldBePresent := exampleType == "bad"

		t.Run(relPath, func(t *testing.T) {
			allIDs := append(meta.Aliases(), id)
			gotIDs, exists := got[relPath]

			var contains bool
			for _, wantID := range allIDs {
				if _, ok := gotIDs[wantID]; ok {
					contains = true
					break
				}
			}

			if shouldBePresent {
				assert.True(t, exists, "expected relPath to exist in got")
				assert.True(t, contains, "expected one of aliases or id to be present")
			} else if exists {
				assert.False(t, contains, "unexpected alias/id found")
			}
		})
		return nil
	})

	require.NoError(t, err)
}

func shouldSkipCheck(
	t *testing.T,
	id string,
	checksMetadata map[string]metadata.Metadata,
	minVersions map[string]semver.Version,
	trivyVer semver.Version,
) bool {
	meta := checksMetadata[id]
	if meta.MinimumTrivyVersion() == "" {
		return false
	}

	// canary always contains the latest changes
	if trivyVer.IsPreRelease() {
		return false
	}

	minVer, ok := minVersions[id]
	if !ok {
		raw := meta.MinimumTrivyVersion()
		var err error
		minVer, err = semver.Parse(raw)
		require.NoError(t, err)
		minVersions[id] = minVer
	}

	return trivyVer.LessThan(minVer)
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
