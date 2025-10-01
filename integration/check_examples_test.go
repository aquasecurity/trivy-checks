//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/registry"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy-checks/integration/testcontainer"
	"github.com/aquasecurity/trivy-checks/internal/bundler"
	"github.com/aquasecurity/trivy-checks/internal/examples"
	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

var trivyVersions = []string{"0.57.1", "0.58.1", "latest", "canary"}

func TestScanCheckExamples(t *testing.T) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp(".", "trivy-checks-examples-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	registryContainer, err := registry.Run(ctx, "registry:2")
	require.NoError(t, err)
	t.Cleanup(func() { registryContainer.Terminate(context.TODO()) })

	registryHost, err := registryContainer.HostAddress(ctx)
	require.NoError(t, err)

	bundleImage := registryHost + "/" + "trivy-checks:latest"

	for _, version := range trivyVersions {
		t.Run(version, func(t *testing.T) {
			verDir := filepath.Join(tmpDir, version)
			examplesPath := filepath.Join(verDir, "examples")

			trivyVer := getActualTrivyVersion(t, version)
			checksMetadata, skipped := setupTarget(t, examplesPath, trivyVer)

			bundlePath := buildBundle(t, verDir, skipped)
			pushBundle(t, ctx, bundlePath, bundleImage)

			targetDir, err := filepath.Abs(verDir)
			require.NoError(t, err)

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

			state, err := trivy.State(t.Context())
			require.NoError(t, err)

			if state.ExitCode != 0 {
				t.Fatal(string(b))
			}

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

			verifyReport(t, report, examplesPath, checksMetadata)
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

func buildBundle(t *testing.T, path string, skipped []string) string {
	t.Helper()

	fsys := os.DirFS("..")
	b := bundler.New(".", fsys, bundler.WithFilters(makeSkipIDFilter(t, skipped, fsys)))

	bundlePath := filepath.Join(path, "bundle.tar.gz")
	f, err := os.Create(bundlePath)
	require.NoError(t, err)

	require.NoError(t, b.Build(f))
	return bundlePath
}

func makeSkipIDFilter(t *testing.T, skipped []string, fsys fs.FS) func(path string) bool {
	skipMap := make(map[string]struct{}, len(skipped))
	for _, id := range skipped {
		skipMap[id] = struct{}{}
	}

	return func(path string) bool {
		if !strings.HasSuffix(path, ".rego") {
			return true
		}

		b, err := fs.ReadFile(fsys, path)
		require.NoError(t, err)

		module, err := ast.ParseModuleWithOpts(path, string(b), ast.ParserOptions{
			ProcessAnnotation: true,
		})
		require.NoError(t, err)

		meta, ok := metadata.GetCheckMetadata(module)
		require.True(t, ok, "failed to get metadata for %s", path)

		if _, found := skipMap[meta.ID()]; found {
			t.Logf("Skip check %s by id filter", meta.ID())
			return false
		}
		return true
	}
}

func pushBundle(t *testing.T, ctx context.Context, path string, image string) {
	t.Helper()

	orasCmd := []string{
		"push", image,
		"--artifact-type", "application/vnd.cncf.openpolicyagent.config.v1+json",
		filepath.Base(path) + ":application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
	}

	absPath, err := filepath.Abs(path)
	require.NoError(t, err)

	c, err := testcontainer.RunOras(ctx, orasCmd,
		testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
			config.NetworkMode = "host"
			config.Mounts = []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: absPath,
					Target: "/" + filepath.Base(path),
				}}
		}),
	)
	require.NoError(t, err)
	require.NoError(t, c.Terminate(ctx))
}

func setupTarget(t *testing.T, targetDir string, trivyVer semver.Version) (map[string]metadata.Metadata, []string) {
	t.Helper()

	checksMetadata, err := metadata.LoadDefaultChecksMetadata()
	require.NoError(t, err)

	metadataByID := make(map[string]metadata.Metadata)
	minVersions := make(map[string]semver.Version)
	var skipped []string

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

		// Trivy filters the checks by the minimum supported version itself,
		// but this feature appeared after some of the checks had already been updated,
		// so here we re-apply filtering for compatibility.
		if shouldSkipCheck(t, meta, minVersions, trivyVer) {
			t.Logf("Skip unsupported check %s for %s", meta.ID(), trivyVer.String())
			skipped = append(skipped, meta.ID())
			continue
		}

		metadataByID[meta.ID()] = meta

		for provider, providerExamples := range checkExamples {
			writeExamples(t, providerExamples.Bad.ToStrings(), provider, targetDir, meta.AVDID(), "bad")
			writeExamples(t, providerExamples.Good.ToStrings(), provider, targetDir, meta.AVDID(), "good")
		}
	}
	return metadataByID, skipped
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
	t *testing.T, results []Result, targetDir string, checksMetadata map[string]metadata.Metadata) {
	t.Helper()

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
	meta metadata.Metadata,
	minVersions map[string]semver.Version,
	trivyVer semver.Version,
) bool {
	if meta.MinimumTrivyVersion() == "" {
		return false
	}

	minVer, ok := minVersions[meta.ID()]
	if !ok {
		var err error
		minVer, err = semver.Parse(meta.MinimumTrivyVersion())
		require.NoError(t, err)
		minVersions[meta.ID()] = minVer
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
