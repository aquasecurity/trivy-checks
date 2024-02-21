package iam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSetMaxPasswordAge(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Password expires in 99 days",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:   trivyTypes.NewTestMetadata(),
					MaxAgeDays: trivyTypes.Int(99, trivyTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Password expires in 60 days",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:   trivyTypes.NewTestMetadata(),
					MaxAgeDays: trivyTypes.Int(60, trivyTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckSetMaxPasswordAge.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSetMaxPasswordAge.LongID() {
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
