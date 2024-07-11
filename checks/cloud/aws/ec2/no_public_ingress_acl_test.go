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

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.NetworkACLRule
		expected bool
	}{
		{
			name: "The rule allow traffic from all possible IPv4 addresses",
			input: ec2.NetworkACLRule{
				Type:   trivyTypes.StringTest(ec2.TypeIngress),
				Action: trivyTypes.StringTest(ec2.ActionAllow),
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("0.0.0.0/0"),
				},
				Protocol: trivyTypes.StringTest("tcp"),
				FromPort: trivyTypes.IntTest(22),
				ToPort:   trivyTypes.IntTest(22),
			},
			expected: true,
		},
		{
			name: "The rule allow traffic from restricted IPv4 addresses",
			input: ec2.NetworkACLRule{
				Type:   trivyTypes.StringTest(ec2.TypeIngress),
				Action: trivyTypes.StringTest(ec2.ActionAllow),
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("10.0.0.0/16"),
				},
				Protocol: trivyTypes.StringTest("-1"),
			},
			expected: false,
		},
		{
			name: "The rule allow traffic from all possible IPv6 addresses",
			input: ec2.NetworkACLRule{
				Type:   trivyTypes.StringTest(ec2.TypeIngress),
				Action: trivyTypes.StringTest(ec2.ActionAllow),
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
			input: ec2.NetworkACLRule{
				Type:   trivyTypes.StringTest(ec2.TypeIngress),
				Action: trivyTypes.StringTest(ec2.ActionAllow),
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("2b5b:1e49:8d01:c2ac:fffd:833e:dfee:13a4/64"),
				},
				Protocol: trivyTypes.StringTest("-1"),
			},
			expected: false,
		},
		{
			name: "The rule deny traffic from all possible IPv4 addresses",
			input: ec2.NetworkACLRule{
				Type:   trivyTypes.StringTest(ec2.TypeIngress),
				Action: trivyTypes.StringTest(ec2.ActionDeny),
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("0.0.0.0/0"),
				},
				Protocol: trivyTypes.StringTest("tcp"),
				FromPort: trivyTypes.IntTest(22),
				ToPort:   trivyTypes.IntTest(22),
			},
			expected: false,
		},
		{
			name: "The rule allow traffic to non administrative ports",
			input: ec2.NetworkACLRule{
				Type:   trivyTypes.StringTest(ec2.TypeIngress),
				Action: trivyTypes.StringTest(ec2.ActionAllow),
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("0.0.0.0/0"),
				},
				Protocol: trivyTypes.StringTest("tcp"),
				FromPort: trivyTypes.IntTest(16),
				ToPort:   trivyTypes.IntTest(16),
			},
			expected: false,
		},
		{
			name: "The egress rule",
			input: ec2.NetworkACLRule{
				Type:   trivyTypes.StringTest(ec2.TypeEgress),
				Action: trivyTypes.StringTest(ec2.ActionAllow),
				CIDRs: []trivyTypes.StringValue{
					trivyTypes.StringTest("0.0.0.0/0"),
				},
				Protocol: trivyTypes.StringTest("tcp"),
				FromPort: trivyTypes.IntTest(22),
				ToPort:   trivyTypes.IntTest(22),
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testState := state.State{
				AWS: aws.AWS{EC2: ec2.EC2{NetworkACLs: []ec2.NetworkACL{
					{
						Rules: []ec2.NetworkACLRule{
							test.input,
						},
					},
				}}},
			}
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
