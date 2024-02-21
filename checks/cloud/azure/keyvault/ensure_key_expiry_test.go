package keyvault

import (
	"testing"
	"time"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/keyvault"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnsureKeyExpiry(t *testing.T) {
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name: "Key vault key expiration date not set",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Keys: []keyvault.Key{
							{
								Metadata:   trivyTypes.NewTestMetadata(),
								ExpiryDate: trivyTypes.Time(time.Time{}, trivyTypes.NewTestMetadata().GetMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Key vault key expiration date specified",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Keys: []keyvault.Key{
							{
								Metadata:   trivyTypes.NewTestMetadata(),
								ExpiryDate: trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata().GetMetadata()),
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
			testState.Azure.KeyVault = test.input
			results := CheckEnsureKeyExpiry.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnsureKeyExpiry.LongID() {
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
