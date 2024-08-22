package test

import (
	"context"
	"testing"

	checks "github.com/aquasecurity/trivy-checks"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	ruleTypes "github.com/aquasecurity/trivy/pkg/iac/types/rules"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func scanState(t *testing.T, regoScanner *rego.Scanner, s state.State, checkID string, expected bool) {
	results, err := regoScanner.ScanInput(context.TODO(), rego.Input{
		Contents: s.ToRego(),
	})
	require.NoError(t, err)

	var found bool
	for _, result := range results {
		if result.Status() == scan.StatusFailed && result.Rule().AVDID == checkID {
			found = true
		}
	}

	if expected {
		assert.True(t, found, "Rule should have been found")
	} else {
		assert.False(t, found, "Rule should not have been found")
	}
}

type testCase struct {
	name     string
	input    state.State
	expected bool
}

type testCases map[string][]testCase

func TestRegoChecks(t *testing.T) {
	tests := lo.Assign(
		awsAccessAnalyzerTestCases,
		awsAthenaTestCases,
		awsCloudTrailTestCases,
		awsCodeBuildTestCases,
		awsConfigTestCases,
		awsDocumentDBTestCases,
		awsDynamodbTestCases,
		awsS3TestCases,

		azureMonitorTestCases,
		azureNetworkTestCases,
		azureSynapseTestCases,
		azureSecurityCenterTestCases,
		azureDataFactoryTestCases,
		azureDataLakeTestCases,
		azureKeyVaultTestCases,
		azureAppServiceTestCases,
		azureAuthorizationTestCases,
		azureContainerTestCases,
		azureDatabaseTestCases,
		azureComputeTestCases,

		googleDnsTestCases,
		googleKmsTestCases,
		googleBigQueryTestCases,

		githubTestCases,

		nifcloudDnsTestCases,
		nifcloudNetworkTestCases,
		nifcloudSslCertificateTestCases,

		digitalOceanSpacesTestCases,
		oracleTestCases,
	)

	regoScanner := rego.NewScanner(trivyTypes.SourceCloud)
	err := regoScanner.LoadPolicies(true, false, checks.EmbeddedPolicyFileSystem, []string{"."}, nil)
	require.NoError(t, err)

	missedIDs, _ := lo.Difference(getMigratedChecksIDs(), lo.Keys(tests))
	assert.Emptyf(t, missedIDs, "Checks %v not covered", missedIDs)

	for id, cases := range tests {
		t.Run(id, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					scanState(t, regoScanner, tc.input, id, tc.expected)
				})
			}
		})
	}
}

func getMigratedChecksIDs() []string {
	allChecks := rules.GetRegistered()

	goChecksIDs := lo.FilterMap(allChecks, func(r ruleTypes.RegisteredRule, _ int) (string, bool) {
		return r.AVDID, r.Check != nil
	})

	regoChecksMap := lo.SliceToMap(lo.Filter(allChecks, func(r ruleTypes.RegisteredRule, _ int) bool {
		return r.Check == nil
	}), func(r ruleTypes.RegisteredRule) (string, any) {
		return r.AVDID, struct{}{}
	})

	return lo.Filter(goChecksIDs, func(avdID string, _ int) bool {
		_, exists := regoChecksMap[avdID]
		return exists
	})
}
