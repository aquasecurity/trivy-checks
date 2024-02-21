package config

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/config"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAggregateAllRegions(t *testing.T) {
	tests := []struct {
		name     string
		input    config.Config
		expected bool
	}{
		{
			name: "AWS Config aggregator source with all regions set to false",
			input: config.Config{
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					Metadata:         trivyTypes.NewTestMetadata(),
					SourceAllRegions: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "AWS Config aggregator source with all regions set to true",
			input: config.Config{
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					Metadata:         trivyTypes.NewTestMetadata(),
					SourceAllRegions: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Config = test.input
			results := CheckAggregateAllRegions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAggregateAllRegions.LongID() {
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
