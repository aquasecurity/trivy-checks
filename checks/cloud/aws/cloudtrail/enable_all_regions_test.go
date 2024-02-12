package cloudtrail

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAllRegions(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudtrail.CloudTrail
		expected bool
	}{
		{
			name: "AWS CloudTrail not enabled across all regions",
			input: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:      defsecTypes.NewTestMetadata(),
						IsMultiRegion: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS CloudTrail enabled across all regions",
			input: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:      defsecTypes.NewTestMetadata(),
						IsMultiRegion: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudTrail = test.input
			results := CheckEnableAllRegions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAllRegions.LongID() {
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
