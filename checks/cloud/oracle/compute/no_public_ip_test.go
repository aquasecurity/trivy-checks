package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/oracle"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIp(t *testing.T) {
	tests := []struct {
		name     string
		input    oracle.Compute
		expected bool
	}{
		{
			name: "Compute instance public reservation pool",
			input: oracle.Compute{
				AddressReservations: []oracle.AddressReservation{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Pool:     defsecTypes.String("public-ippool", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Compute instance cloud reservation pool",
			input: oracle.Compute{
				AddressReservations: []oracle.AddressReservation{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Pool:     defsecTypes.String("cloud-ippool", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Oracle.Compute = test.input
			results := CheckNoPublicIp.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIp.LongID() {
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
