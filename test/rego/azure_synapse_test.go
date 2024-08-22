package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/synapse"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var azureSynapseTestCases = testCases{
	"AVD-AZU-0034": {
		{
			name: "Synapse workspace managed VN disabled",
			input: state.State{Azure: azure.Azure{Synapse: synapse.Synapse{
				Workspaces: []synapse.Workspace{
					{
						Metadata:                    trivyTypes.NewTestMetadata(),
						EnableManagedVirtualNetwork: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Synapse workspace managed VN enabled",
			input: state.State{Azure: azure.Azure{Synapse: synapse.Synapse{
				Workspaces: []synapse.Workspace{
					{
						Metadata:                    trivyTypes.NewTestMetadata(),
						EnableManagedVirtualNetwork: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
