package ec2

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

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
						Metadata: defsecTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     defsecTypes.NewTestMetadata(),
							HttpTokens:   defsecTypes.String("optional", defsecTypes.NewTestMetadata()),
							HttpEndpoint: defsecTypes.String("enabled", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     defsecTypes.NewTestMetadata(),
							HttpTokens:   defsecTypes.String("required", defsecTypes.NewTestMetadata()),
							HttpEndpoint: defsecTypes.String("disabled", defsecTypes.NewTestMetadata()),
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
