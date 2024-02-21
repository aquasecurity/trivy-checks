package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Firewall egress rule with multiple public destination addresses",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: trivyTypes.NewTestMetadata(),
							EgressRules: []compute.EgressRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: trivyTypes.NewTestMetadata(),
										IsAllow:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										Enforced: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
									DestinationRanges: []trivyTypes.StringValue{
										trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
										trivyTypes.String("1.2.3.4/32", trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall egress rule with public destination address",
			input: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: trivyTypes.NewTestMetadata(),
							EgressRules: []compute.EgressRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: trivyTypes.NewTestMetadata(),
										IsAllow:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										Enforced: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
									DestinationRanges: []trivyTypes.StringValue{
										trivyTypes.String("1.2.3.4/32", trivyTypes.NewTestMetadata()),
									},
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
			testState.Google.Compute = test.input
			results := CheckNoPublicEgress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicEgress.LongID() {
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
