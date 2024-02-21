package storage

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Storage account container public access set to blob",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								PublicAccess: trivyTypes.String(storage.PublicAccessBlob, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage account container public access set to container",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								PublicAccess: trivyTypes.String(storage.PublicAccessContainer, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage account container public access set to off",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								PublicAccess: trivyTypes.String(storage.PublicAccessOff, trivyTypes.NewTestMetadata()),
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
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.LongID() {
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
