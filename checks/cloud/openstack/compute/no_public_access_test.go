package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/openstack"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    openstack.Compute
		expected bool
	}{
		{
			name: "Firewall rule missing destination address",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    trivyTypes.NewTestMetadata(),
							Enabled:     trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Destination: trivyTypes.String("", trivyTypes.NewTestMetadata()),
							Source:      trivyTypes.String("10.10.10.1", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule missing source address",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    trivyTypes.NewTestMetadata(),
							Enabled:     trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Destination: trivyTypes.String("10.10.10.2", trivyTypes.NewTestMetadata()),
							Source:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule with public destination and source addresses",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    trivyTypes.NewTestMetadata(),
							Enabled:     trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Destination: trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
							Source:      trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Firewall rule with private destination and source addresses",
			input: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    trivyTypes.NewTestMetadata(),
							Enabled:     trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Destination: trivyTypes.String("10.10.10.1", trivyTypes.NewTestMetadata()),
							Source:      trivyTypes.String("10.10.10.2", trivyTypes.NewTestMetadata()),
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
			testState.OpenStack.Compute = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.LongID() {
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
