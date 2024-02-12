package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableVPCFlowLogs(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Subnetwork VPC flow logs disabled",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       defsecTypes.NewTestMetadata(),
								EnableFlowLogs: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Subnetwork VPC flow logs enabled",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       defsecTypes.NewTestMetadata(),
								EnableFlowLogs: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Proxy-only subnets and logs disabled",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       defsecTypes.NewTestMetadata(),
								EnableFlowLogs: defsecTypes.BoolDefault(false, defsecTypes.NewTestMetadata()),
								Purpose:        defsecTypes.String("REGIONAL_MANAGED_PROXY", defsecTypes.NewTestMetadata()),
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
			testState.Google.Compute = test.input
			results := CheckEnableVPCFlowLogs.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableVPCFlowLogs.LongID() {
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
