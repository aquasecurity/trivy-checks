package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/cloudstack"
	"github.com/aquasecurity/trivy/pkg/iac/providers/cloudstack/compute"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(cloudStackTestCases)
}

var cloudStackTestCases = testCases{
	"AVD-CLDSTK-0001": {
		{
			name: "Compute instance with sensitive information in user data",
			input: state.State{CloudStack: cloudstack.CloudStack{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						UserData: trivyTypes.String(` export DATABASE_PASSWORD=\"SomeSortOfPassword\"`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Compute instance with no sensitive information in user data",
			input: state.State{CloudStack: cloudstack.CloudStack{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						UserData: trivyTypes.String(` export GREETING="Hello there"`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
