package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/compute"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDisablePasswordAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Linux VM password authentication enabled",
			input: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
							Metadata:                      trivyTypes.NewTestMetadata(),
							DisablePasswordAuthentication: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Linux VM password authentication disabled",
			input: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
							Metadata:                      trivyTypes.NewTestMetadata(),
							DisablePasswordAuthentication: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.Azure.Compute = test.input
			results := CheckDisablePasswordAuthentication.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDisablePasswordAuthentication.LongID() {
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
