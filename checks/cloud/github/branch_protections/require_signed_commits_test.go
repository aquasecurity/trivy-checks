package branch_protections

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/github"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRequireSignedCommits(t *testing.T) {
	tests := []struct {
		name     string
		input    []github.BranchProtection
		expected bool
	}{
		{
			name: "Require signed commits enabled for branch",
			input: []github.BranchProtection{
				{
					Metadata:             trivyTypes.NewTestMetadata(),
					RequireSignedCommits: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
		{
			name: "Require signed commits disabled for repository",
			input: []github.BranchProtection{
				{
					Metadata:             trivyTypes.NewTestMetadata(),
					RequireSignedCommits: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.GitHub.BranchProtections = test.input
			results := CheckRequireSignedCommits.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != scan.StatusPassed && result.Rule().LongID() == CheckRequireSignedCommits.LongID() {
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
