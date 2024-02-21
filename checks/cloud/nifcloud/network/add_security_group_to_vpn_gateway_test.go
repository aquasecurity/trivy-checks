package network

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/network"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAddSecurityGroupToVpnGateway(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "NIFCLOUD vpnGateway with no security group provided",
			input: network.Network{
				VpnGateways: []network.VpnGateway{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						SecurityGroup: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD vpnGateway with security group",
			input: network.Network{
				VpnGateways: []network.VpnGateway{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						SecurityGroup: trivyTypes.String("some security group", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.Network = test.input
			results := CheckAddSecurityGroupToVpnGateway.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAddSecurityGroupToVpnGateway.LongID() {
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
