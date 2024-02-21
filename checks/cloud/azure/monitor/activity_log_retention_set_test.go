package monitor

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/monitor"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckActivityLogRetentionSet(t *testing.T) {
	tests := []struct {
		name     string
		input    monitor.Monitor
		expected bool
	}{
		{
			name: "Log retention policy disabled",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							Days:     trivyTypes.Int(365, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log retention policy enabled for 90 days",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Days:     trivyTypes.Int(90, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log retention policy enabled for 365 days",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RetentionPolicy: monitor.RetentionPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Days:     trivyTypes.Int(365, trivyTypes.NewTestMetadata()),
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
			results := CheckActivityLogRetentionSet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckActivityLogRetentionSet.LongID() {
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
