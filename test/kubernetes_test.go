package test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Kubenetes(t *testing.T) {
	tests := []struct {
		name string
		opts []options.ScannerOption
	}{
		{
			name: "checks from disk",
			opts: []options.ScannerOption{
				rego.WithPolicyFilesystem(os.DirFS("../checks/kubernetes")),
				rego.WithPolicyDirs("."),
			},
		},
		{
			name: "embedded checks",
			opts: []options.ScannerOption{
				rego.WithEmbeddedPolicies(true),
			},
		},
	}

	testdata := "./testdata/kubernetes"

	entries, err := os.ReadDir(testdata)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(t.Name(), func(t *testing.T) {
			t.Parallel()

			opts := []options.ScannerOption{
				rego.WithPerResultTracing(true),
				rego.WithEmbeddedLibraries(true),
				rego.WithIncludeDeprecatedChecks(false),
			}
			opts = append(opts, tt.opts...)

			scanner := kubernetes.NewScanner(opts...)

			results, err := scanner.ScanFS(context.TODO(), os.DirFS(testdata), ".")
			require.NoError(t, err)

			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				if entry.Name() == "optional" {
					continue
				}

				dirName := entry.Name()

				t.Run(entry.Name(), func(t *testing.T) {
					assertChecks(t, dirName,
						fmt.Sprintf("%s/denied.yaml", dirName),
						fmt.Sprintf("%s/allowed.yaml", dirName),
						results,
					)
				})
			}
		})
	}
}

func assertChecks(t *testing.T, fileName, failCase, passCase string, results scan.Results) {
	t.Helper()

	var matched bool

	for _, result := range results {
		if !result.Rule().HasID(fileName) {
			continue
		}

		t.Run(result.Rule().AVDID, func(t *testing.T) {
			switch result.Range().GetFilename() {
			case failCase:
				assert.Equal(t, scan.StatusFailed, result.Status(), "Rule should have failed, but didn't.")
				if result.Rule().AVDID != "AVD-DS-0002" {
					assert.Greater(t, result.Range().GetStartLine(), 0, "We should have line numbers for a failure")
					assert.Greater(t, result.Range().GetEndLine(), 0, "We should have line numbers for a failure")
				}
				matched = true
			case passCase:
				assert.Equal(t, scan.StatusPassed, result.Status(), "Rule should have passed, but didn't.")
				matched = true
			default:
				return
			}

			if t.Failed() {
				fmt.Println("Test failed - rego trace follows:")
				for _, trace := range result.Traces() {
					fmt.Println(trace)
				}
			}
		})
	}

	assert.True(t, matched, "Rule should be matched once")
}
