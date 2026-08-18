//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/registry"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy-checks/internal/examples"
	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

var trivyVersions = []string{"0.61.0", "latest", "canary"}

// reportFileName is written next to the examples directory each subtest works in,
// so it needs no per-version prefix.
const reportFileName = "report.json"

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

	versions := trivyVersions
	if localTrivyBinary != "" {
		versions = []string{"local"}
	}

	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			verDir := filepath.Join(tmpDir, version)
			examplesPath := filepath.Join(verDir, "examples")

			targetDir, err := filepath.Abs(verDir)
			require.NoError(t, err)

			target := newTrivyTarget(ctx, version, targetDir)

			trivyVer := getActualTrivyVersion(t, target)
			checksMetadata, skipped := setupTarget(t, examplesPath, trivyVer)

			bundlePath := buildBundle(t, verDir, skipped, trivyVer)
			pushBundle(t, ctx, bundlePath, bundleImage)

			args := []string{
				"conf",
				"--checks-bundle-repository", bundleImage,
				"--format", "json",
				"--output", target.Path(reportFileName),
				"--include-deprecated-checks=false",
				target.Path("examples"),
			}

			out, err := target.Run(args)
			if err != nil {
				t.Fatalf("trivy run failed: %v\n%s", err, out)
			}

			// trivy switches to embedded checks if the bundle load fails, so we should check this out
			if bytes.Contains(out, []byte("Falling back to embedded checks")) {
				t.Log(string(out))
				t.Fatal("Failed to load checks from the bundle")
			}

			report := readTrivyReport(t, filepath.Join(targetDir, reportFileName))

			verifyReport(t, report, examplesPath, checksMetadata)
		})
	}
}

func getActualTrivyVersion(t *testing.T, target trivyTarget) semver.Version {
	t.Helper()

	b, err := target.VersionJSON()
	require.NoError(t, err)

	t.Logf("Version response: %q", string(b))

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

func setupTarget(t *testing.T, targetDir string, trivyVer semver.Version) (map[string]metadata.Metadata, []string) {
	t.Helper()

	checksMetadata, err := metadata.LoadDefaultChecksMetadata()
	require.NoError(t, err)

	metadataByID := make(map[string]metadata.Metadata)
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
		if shouldSkipCheck(t, meta, trivyVer) {
			t.Logf("Skip unsupported check %s for %s", meta.ID(), trivyVer.String())
			skipped = append(skipped, meta.ID())
			continue
		}

		metadataByID[meta.ID()] = meta

		for provider, providerExamples := range checkExamples {
			writeExamples(t, providerExamples.Bad.ToStrings(), provider, targetDir, meta.ID(), "bad")
			writeExamples(t, providerExamples.Good.ToStrings(), provider, targetDir, meta.ID(), "good")
		}
	}
	return metadataByID, skipped
}

func writeExamples(t *testing.T, examples []string, provider, cacheDir string, id string, typ string) {
	t.Helper()

	for i, example := range examples {
		file := examplePath(cacheDir, id, provider, typ, i)
		require.NoError(t, os.MkdirAll(filepath.Dir(file), fs.ModePerm))
		require.NoError(t, os.WriteFile(file, []byte(example), fs.ModePerm))
	}
}

// examplePath builds the path of a single example: <id>/<provider>/<good|bad>/<index>/<file>.
// parseExamplePath takes such a path apart again, so both must be changed together.
func examplePath(root, id, provider, typ string, index int) string {
	return filepath.Join(root, id, provider, typ, strconv.Itoa(index), fileNameByProvider(provider))
}

func parseExamplePath(t *testing.T, relPath string) (id, typ string) {
	t.Helper()

	parts := strings.Split(relPath, string(os.PathSeparator))
	require.Len(t, parts, 5, "unexpected example layout %q", relPath)

	return parts[0], parts[2]
}

func verifyReport(
	t *testing.T, results []Result, targetDir string, checksMetadata map[string]metadata.Metadata) {
	t.Helper()

	got := getFailureIDs(results)
	err := filepath.WalkDir(targetDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(targetDir, path)
		require.NoError(t, err)

		id, exampleType := parseExamplePath(t, relPath)

		meta := checksMetadata[id]
		shouldBePresent := exampleType == "bad"

		t.Run(relPath, func(t *testing.T) {
			allIDs := append(meta.Aliases(), id)
			gotIDs, exists := got[relPath]

			contains := slices.ContainsFunc(allIDs, func(wantID string) bool {
				_, ok := gotIDs[wantID]
				return ok
			})

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

func shouldSkipCheck(t *testing.T, meta metadata.Metadata, trivyVer semver.Version) bool {
	if meta.MinimumTrivyVersion() == "" || trivyVer.IsPreRelease() {
		return false
	}

	minVer, err := semver.Parse(meta.MinimumTrivyVersion())
	require.NoError(t, err)

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
