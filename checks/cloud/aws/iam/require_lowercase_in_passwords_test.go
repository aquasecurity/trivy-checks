package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireLowercaseInPasswords(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "IAM password policy lowercase not required",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         defsecTypes.NewTestMetadata(),
					RequireLowercase: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "IAM password policy lowercase required",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         defsecTypes.NewTestMetadata(),
					RequireLowercase: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckRequireLowercaseInPasswords.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireLowercaseInPasswords.LongID() {
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
