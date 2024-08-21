package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/datalake"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var azureDataLakeTestCases = testCases{
	"AVD-AZU-0036": {
		{
			name: "unencrypted Data Lake store",
			input: state.State{Azure: azure.Azure{DataLake: datalake.DataLake{
				Stores: []datalake.Store{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						EnableEncryption: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "encrypted Data Lake store",
			input: state.State{Azure: azure.Azure{DataLake: datalake.DataLake{
				Stores: []datalake.Store{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						EnableEncryption: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
