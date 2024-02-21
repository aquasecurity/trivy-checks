package computing

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/computing"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoCommonPrivateInstance(t *testing.T) {
	tests := []struct {
		name     string
		input    computing.Computing
		expected bool
	}{
		{
			name: "NIFCLOUD instance with common private",
			input: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []computing.NetworkInterface{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								NetworkID: trivyTypes.String("net-COMMON_PRIVATE", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD instance with private LAN",
			input: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []computing.NetworkInterface{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								NetworkID: trivyTypes.String("net-some-private-lan", trivyTypes.NewTestMetadata()),
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
			testState.Nifcloud.Computing = test.input
			results := CheckNoCommonPrivateInstance.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoCommonPrivateInstance.LongID() {
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
