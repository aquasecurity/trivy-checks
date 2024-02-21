package storage

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDefaultActionDeny(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Storage network rule allows access by default",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata:       trivyTypes.NewTestMetadata(),
								AllowByDefault: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage network rule denies access by default",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata:       trivyTypes.NewTestMetadata(),
								AllowByDefault: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
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
			testState.Azure.Storage = test.input
			results := CheckDefaultActionDeny.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDefaultActionDeny.LongID() {
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
