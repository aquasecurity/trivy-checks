package cloudwatch

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudwatch"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLogGroupCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudwatch.CloudWatch
		expected bool
	}{
		{
			name: "AWS CloudWatch with unencrypted log group",
			input: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS CloudWatch with encrypted log group",
			input: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudWatch = test.input
			results := CheckLogGroupCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLogGroupCustomerKey.LongID() {
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
