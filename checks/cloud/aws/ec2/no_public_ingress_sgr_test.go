package ec2

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestCheckNoPublicIngressSgr(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.SecurityGroupRule
		expected bool
	}{
		{
			name: "The rule allow traffic from all possible IPv4 addresses",
			input: ec2.SecurityGroupRule{
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("0.0.0.0/0"),
				},
				Protocol: trivyTypes.StringTest("-1"),
			},
			expected: true,
		},
		{
			name: "The rule allow traffic from restricted IPv4 addresses",
			input: ec2.SecurityGroupRule{
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("10.0.0.0/16"),
				},
				Protocol: trivyTypes.StringTest("-1"),
			},
			expected: false,
		},
		{
			name: "The rule allow traffic from all possible IPv6 addresses",
			input: ec2.SecurityGroupRule{
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("::/0"),
					trivyTypes.StringTest("0000:0000:0000:0000:0000:0000:0000:0000/0"),
				},
				Protocol: trivyTypes.StringTest("-1"),
			},
			expected: true,
		},
		{
			name: "The rule allow traffic from restricted IPv6 addresses",
			input: ec2.SecurityGroupRule{
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("5be8:dde9:7f0b:d5a7:bd01:b3be:9c69:573b/64"),
				},
				Protocol: trivyTypes.StringTest("-1"),
			},
			expected: false,
		},
		{
			name: "The rule allow traffic to non administrative ports",
			input: ec2.SecurityGroupRule{
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("0.0.0.0/0"),
				},
				Protocol: trivyTypes.StringTest("tcp"),
				FromPort: trivyTypes.IntTest(1024),
				ToPort:   trivyTypes.IntTest(1024),
			},
			expected: false,
		},
		{
			name: "The rule allow traffic to all ports",
			input: ec2.SecurityGroupRule{
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("0.0.0.0/0"),
				},
				Protocol: trivyTypes.StringTest("-1"),
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testState := state.State{
				AWS: aws.AWS{
					EC2: ec2.EC2{
						SecurityGroups: []ec2.SecurityGroup{
							{
								IngressRules: []ec2.SecurityGroupRule{test.input},
							},
						},
					},
				},
			}
			results := CheckNoPublicIngressSgr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngressSgr.LongID() {
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
