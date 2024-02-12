package ssm

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ssm"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSecretUseCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    ssm.SSM
		expected bool
	}{
		{
			name: "AWS SSM missing KMS key",
			input: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						KMSKeyID: defsecTypes.String("", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS SSM with default KMS key",
			input: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						KMSKeyID: defsecTypes.String(ssm.DefaultKMSKeyID, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS SSM with proper KMS key",
			input: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						KMSKeyID: defsecTypes.String("some-ok-key", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SSM = test.input
			results := CheckSecretUseCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSecretUseCustomerKey.LongID() {
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
