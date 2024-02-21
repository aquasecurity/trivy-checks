package repositories

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/github"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckPrivate(t *testing.T) {
	tests := []struct {
		name     string
		input    []github.Repository
		expected bool
	}{
		{
			name: "Public repository",
			input: []github.Repository{
				{
					Metadata: trivyTypes.NewTestMetadata(),
					Public:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Private repository",
			input: []github.Repository{
				{
					Metadata: trivyTypes.NewTestMetadata(),
					Public:   trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.GitHub.Repositories = test.input
			results := CheckPrivate.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckPrivate.LongID() {
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
