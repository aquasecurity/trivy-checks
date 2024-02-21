package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireSupportRole(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name:     "No support role",
			input:    iam.IAM{},
			expected: true,
		},
		{
			name: "Has support role",
			input: iam.IAM{
				Roles: []iam.Role{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("example", defsecTypes.NewTestMetadata()),
						Policies: []iam.Policy{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Builtin:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
								Name:     defsecTypes.String("AWSSupportRole", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckRequireSupportRole.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireSupportRole.LongID() {
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
