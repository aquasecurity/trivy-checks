package redshift

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/redshift"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAddDescriptionToSecurityGroup(t *testing.T) {
	tests := []struct {
		name     string
		input    redshift.Redshift
		expected bool
	}{
		{
			name: "Redshift security group without description",
			input: redshift.Redshift{
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Redshift security group with description",
			input: redshift.Redshift{
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("security group description", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Redshift = test.input
			results := CheckAddDescriptionToSecurityGroup.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAddDescriptionToSecurityGroup.LongID() {
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
