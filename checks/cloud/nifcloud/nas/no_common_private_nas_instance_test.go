package nas

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/nas"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoCommonPrivateNASInstance(t *testing.T) {
	tests := []struct {
		name     string
		input    nas.NAS
		expected bool
	}{
		{
			name: "NIFCLOUD nas instance with common private",
			input: nas.NAS{
				NASInstances: []nas.NASInstance{
					{
						Metadata:  defsecTypes.NewTestMetadata(),
						NetworkID: defsecTypes.String("net-COMMON_PRIVATE", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD nas instance with private LAN",
			input: nas.NAS{
				NASInstances: []nas.NASInstance{
					{
						Metadata:  defsecTypes.NewTestMetadata(),
						NetworkID: defsecTypes.String("net-some-private-lan", defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.NAS = test.input
			results := CheckNoCommonPrivateNASInstance.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoCommonPrivateNASInstance.LongID() {
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
