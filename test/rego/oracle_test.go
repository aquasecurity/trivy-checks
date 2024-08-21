package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/oracle"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var oracleTestCases = testCases{
	"AVD-OCI-0001": {
		{
			name: "Compute instance public reservation pool",
			input: state.State{Oracle: oracle.Oracle{Compute: oracle.Compute{
				AddressReservations: []oracle.AddressReservation{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Pool:     trivyTypes.String("public-ippool", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Compute instance cloud reservation pool",
			input: state.State{Oracle: oracle.Oracle{Compute: oracle.Compute{
				AddressReservations: []oracle.AddressReservation{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Pool:     trivyTypes.String("cloud-ippool", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
