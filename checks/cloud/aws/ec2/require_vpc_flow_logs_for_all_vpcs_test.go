package ec2

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireVPCFlowLogs(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "VPC without flow logs enabled",
			input: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						ID:              trivyTypes.String("vpc-12345678", trivyTypes.NewTestMetadata()),
						FlowLogsEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "VPC with flow logs enabled",
			input: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						ID:              trivyTypes.String("vpc-12345678", trivyTypes.NewTestMetadata()),
						FlowLogsEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			results := CheckRequireVPCFlowLogs.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireVPCFlowLogs.LongID() {
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
