package ec2

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "AWS VPC network ACL rule with wildcard address",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Type:     trivyTypes.String(ec2.TypeIngress, trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String(ec2.ActionAllow, trivyTypes.NewTestMetadata()),
								CIDRs: []trivyTypes.StringValue{
									trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with private address",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Type:     trivyTypes.String(ec2.TypeIngress, trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String(ec2.ActionAllow, trivyTypes.NewTestMetadata()),
								CIDRs: []trivyTypes.StringValue{
									trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
								},
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
			results := CheckNoPublicIngress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngress.LongID() {
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
