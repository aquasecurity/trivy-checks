//go:build integration

package integration

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy-checks/integration/testcontainer"
	"github.com/aquasecurity/trivy-checks/internal/bundler"
	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

func buildBundle(t *testing.T, outputDir string, skipped []string, trivyVer semver.Version) string {
	t.Helper()

	fsys := os.DirFS("..")
	opts := []bundler.Option{
		bundler.WithFilters(skipCheckByIdFilter(t, skipped, fsys)),
	}

	if trivyVer.IsPreRelease() {
		opts = append(opts, bundler.WithPlainTransforms(overrideMinimumVersionTransform(t, trivyVer)))
	}

	b := bundler.New(".", fsys, opts...)

	bundlePath := filepath.Join(outputDir, "bundle.tar.gz")
	f, err := os.Create(bundlePath)
	require.NoError(t, err)

	require.NoError(t, b.Build(f))
	return bundlePath
}

func skipCheckByIdFilter(t *testing.T, skipped []string, fsys fs.FS) bundler.FileFilter {
	skipMap := make(map[string]struct{}, len(skipped))
	for _, id := range skipped {
		skipMap[id] = struct{}{}
	}

	return func(path string) bool {
		if !isRegoFile(path) {
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

var minVerRe = regexp.MustCompile(`#\s+minimum_trivy_version:\s*(\S+)`)

func overrideMinimumVersionTransform(t *testing.T, trivyVersion semver.Version) bundler.PlainTransform {
	return func(path string, raw []byte) []byte {
		if !isRegoFile(path) {
			return raw
		}
		return minVerRe.ReplaceAllFunc(raw, func(match []byte) []byte {
			matches := minVerRe.FindSubmatch(match)
			if len(matches) < 2 {
				return match
			}

			currentVersionStr := string(matches[1])
			currentVersion, err := semver.Parse(currentVersionStr)
			if err != nil {
				return match
			}

			if currentVersion.GreaterThan(trivyVersion) {
				t.Logf("Minimum check version in %s overridden: %s -> %s",
					filepath.Base(path), currentVersionStr, trivyVersion.String())
				return fmt.Appendf(nil, "#   minimum_trivy_version: %s", trivyVersion.String())
			}
			return match
		})
	}
}

func isRegoFile(path string) bool {
	return strings.HasSuffix(path, ".rego")
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
					Target: "/workspace/" + filepath.Base(path),
				}}
		}),
	)
	require.NoError(t, err)
	require.NoError(t, c.Terminate(ctx))
}
