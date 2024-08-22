package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/datafactory"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(azureDataFactoryTestCases)
}

var azureDataFactoryTestCases = testCases{
	"AVD-AZU-0035": {
		{
			name: "Data Factory public access enabled",
			input: state.State{Azure: azure.Azure{DataFactory: datafactory.DataFactory{
				DataFactories: []datafactory.Factory{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						EnablePublicNetwork: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Data Factory public access disabled",
			input: state.State{Azure: azure.Azure{DataFactory: datafactory.DataFactory{
				DataFactories: []datafactory.Factory{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						EnablePublicNetwork: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
