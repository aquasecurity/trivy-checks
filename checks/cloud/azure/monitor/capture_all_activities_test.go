package monitor

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/monitor"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckCaptureAllActivities(t *testing.T) {
	tests := []struct {
		name     string
		input    monitor.Monitor
		expected bool
	}{
		{
			name: "Log profile captures only write activities",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Categories: []trivyTypes.StringValue{
							trivyTypes.String("Write", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log profile captures action, write, delete activities",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Categories: []trivyTypes.StringValue{
							trivyTypes.String("Action", trivyTypes.NewTestMetadata()),
							trivyTypes.String("Write", trivyTypes.NewTestMetadata()),
							trivyTypes.String("Delete", trivyTypes.NewTestMetadata()),
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
			testState.Azure.Monitor = test.input
			results := CheckCaptureAllActivities.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckCaptureAllActivities.LongID() {
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
