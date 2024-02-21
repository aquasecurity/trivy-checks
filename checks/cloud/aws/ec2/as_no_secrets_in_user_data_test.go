package ec2

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestASCheckNoSecretsInUserData(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "Launch template with sensitive info in user data",
			input: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: trivyTypes.NewTestMetadata(),
							UserData: trivyTypes.String(`
							export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
							export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
							export AWS_DEFAULT_REGION=us-west-2
							`, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch template with no sensitive info in user data",
			input: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: trivyTypes.NewTestMetadata(),
							UserData: trivyTypes.String(`
							export GREETING=hello
							`, trivyTypes.NewTestMetadata()),
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
			results := CheckASNoSecretsInUserData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckASNoSecretsInUserData.LongID() {
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
