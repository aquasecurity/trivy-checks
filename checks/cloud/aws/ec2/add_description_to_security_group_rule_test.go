package ec2

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAddDescriptionToSecurityGroupRule(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "AWS VPC security group rule has no description",
			input: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    trivyTypes.NewTestMetadata(),
								Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC security group rule has description",
			input: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    trivyTypes.NewTestMetadata(),
								Description: trivyTypes.String("some description", trivyTypes.NewTestMetadata()),
							},
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
			results := CheckAddDescriptionToSecurityGroupRule.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAddDescriptionToSecurityGroupRule.LongID() {
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
