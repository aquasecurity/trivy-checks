package test

import (
	"context"
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/aquasecurity/trivy-checks/internal/checks"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform"
	"github.com/stretchr/testify/require"
)

func TestCheckExamples(t *testing.T) {
	opts := []options.ScannerOption{
		rego.WithEmbeddedLibraries(true),
		rego.WithEmbeddedPolicies(true),
	}
	tfScanner := terraform.New(opts...)
	cfScanner := cloudformation.New(opts...)

	for _, check := range checks.LoadRegoChecks() {
		t.Run(check.AVDID, func(t *testing.T) {
			exmpls, err := checks.GetCheckExamples(check)
			require.NoError(t, err)

			for i, example := range exmpls {
				s := getScannerForProvider(example.Provider, tfScanner, cfScanner)
				require.NotNil(t, s)
				t.Run(fmt.Sprintf("%s_%d", example.Provider, i), func(t *testing.T) {
					scanExample(t, s, check.LongID(), example)
				})
			}
		})
	}
}

func getScannerForProvider(provider checks.Provider, tfScanner, cfScanner scanner) scanner {
	switch provider {
	case checks.TerraformProvider:
		return tfScanner
	case checks.CloudFormationProvider:
		return cfScanner
	default:
		return nil
	}
}

type scanner interface {
	ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error)
}

func scanExample(t *testing.T, s scanner, checkID string, example *checks.Example) {
	var filename string
	switch example.Provider {
	case checks.TerraformProvider:
		filename = fmt.Sprintf("%s.tf", checkID)
	case checks.CloudFormationProvider:
		filename = fmt.Sprintf("%s.yaml", checkID)
	}

	fsys := fstest.MapFS{
		filename: &fstest.MapFile{
			Data: []byte(example.Content),
		},
	}

	res, err := s.ScanFS(context.TODO(), fsys, ".")
	require.NoError(t, err)

	assertResultContainsCheck(t, res, checkID, example)
}

func assertResultContainsCheck(t *testing.T, results scan.Results, checkID string, example *checks.Example) {
	contains := resultsContainsCheck(results, checkID, example.GoodExample)
	if !contains {
		exampleType := "good"
		if !example.GoodExample {
			exampleType = "bad"
		}
		t.Fatalf("results do not contain check %q for %s example: %s",
			checkID, exampleType, example.Content)
	}
}

func resultsContainsCheck(results scan.Results, checkID string, good bool) bool {
	if good {
		results = results.GetPassed()
	} else {
		results = results.GetFailed()
	}

	for _, result := range results {
		if result.Rule().LongID() == checkID {
			return true
		}
	}

	return false
}
