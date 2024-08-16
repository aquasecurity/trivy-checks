package ec2

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoExcessivePortAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("-1", trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String("allow", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("all", trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String("allow", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with tcp protocol",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("tcp", trivyTypes.NewTestMetadata()),
								Type:     trivyTypes.String("egress", trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String("allow", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Deny with protocol set to all",
			input: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("all", trivyTypes.NewTestMetadata()),
								Type:     trivyTypes.String("ingress", trivyTypes.NewTestMetadata()),
								Action:   trivyTypes.String("deny", trivyTypes.NewTestMetadata()),
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
			results := CheckNoExcessivePortAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoExcessivePortAccess.LongID() {
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
