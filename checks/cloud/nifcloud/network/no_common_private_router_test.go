package network

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/network"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoCommonPrivateRouter(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "NIFCLOUD router with common private",
			input: network.Network{
				Routers: []network.Router{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								NetworkID: defsecTypes.String("net-COMMON_PRIVATE", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD router with private LAN",
			input: network.Network{
				Routers: []network.Router{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								NetworkID: defsecTypes.String("net-some-private-lan", defsecTypes.NewTestMetadata()),
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
			testState.Nifcloud.Network = test.input
			results := CheckNoCommonPrivateRouter.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoCommonPrivateRouter.LongID() {
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
