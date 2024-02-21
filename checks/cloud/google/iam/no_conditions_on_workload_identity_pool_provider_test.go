package iam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoConditionOnWorkloadIdentityPoolProvider(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Workload identity pool without condition",
			input: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       trivyTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         trivyTypes.String("example-pool", trivyTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: trivyTypes.String("example-provider", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Workload identity pool with empty condition",
			input: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       trivyTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         trivyTypes.String("example-pool", trivyTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: trivyTypes.String("example-provider", trivyTypes.NewTestMetadata()),
						AttributeCondition:             trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Workload identity pool with non-empty condition",
			input: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       trivyTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         trivyTypes.String("example-pool", trivyTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: trivyTypes.String("example-provider", trivyTypes.NewTestMetadata()),
						AttributeCondition:             trivyTypes.String("assertion.repository_owner=='your-github-organization'", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.IAM = test.input
			results := CheckNoConditionOnWorkloadIdentityPoolProvider.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoConditionOnWorkloadIdentityPoolProvider.LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
