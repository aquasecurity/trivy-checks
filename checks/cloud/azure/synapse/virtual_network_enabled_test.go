package synapse

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/synapse"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckVirtualNetworkEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    synapse.Synapse
		expected bool
	}{
		{
			name: "Synapse workspace managed VN disabled",
			input: synapse.Synapse{
				Workspaces: []synapse.Workspace{
					{
						Metadata:                    trivyTypes.NewTestMetadata(),
						EnableManagedVirtualNetwork: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Synapse workspace managed VN enabled",
			input: synapse.Synapse{
				Workspaces: []synapse.Workspace{
					{
						Metadata:                    trivyTypes.NewTestMetadata(),
						EnableManagedVirtualNetwork: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.Synapse = test.input
			results := CheckVirtualNetworkEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckVirtualNetworkEnabled.LongID() {
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
