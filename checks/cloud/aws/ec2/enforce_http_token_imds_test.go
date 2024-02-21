package ec2

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckIMDSAccessRequiresToken(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "positive result",
			input: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     trivyTypes.NewTestMetadata(),
							HttpTokens:   trivyTypes.String("optional", trivyTypes.NewTestMetadata()),
							HttpEndpoint: trivyTypes.String("enabled", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "negative result",
			input: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     trivyTypes.NewTestMetadata(),
							HttpTokens:   trivyTypes.String("required", trivyTypes.NewTestMetadata()),
							HttpEndpoint: trivyTypes.String("disabled", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EC2 = test.input
			results := CheckIMDSAccessRequiresToken.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckIMDSAccessRequiresToken.LongID() {
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
