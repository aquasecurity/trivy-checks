package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/digitalocean/compute"
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
			name: "Firewall outbound rule with multiple public destination addresses",
			input: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						OutboundRules: []compute.OutboundFirewallRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								DestinationAddresses: []trivyTypes.StringValue{
									trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
									trivyTypes.String("::/0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall outbound rule with a private destination address",
			input: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						OutboundRules: []compute.OutboundFirewallRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								DestinationAddresses: []trivyTypes.StringValue{
									trivyTypes.String("192.168.1.0/24", trivyTypes.NewTestMetadata()),
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
			testState.DigitalOcean.Compute = test.input
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
