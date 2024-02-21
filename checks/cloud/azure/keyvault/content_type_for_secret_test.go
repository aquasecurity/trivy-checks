package keyvault

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/keyvault"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckContentTypeForSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name: "Key vault secret content-type not specified",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:    trivyTypes.NewTestMetadata(),
								ContentType: trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Key vault secret content-type specified",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:    trivyTypes.NewTestMetadata(),
								ContentType: trivyTypes.String("password", trivyTypes.NewTestMetadata()),
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
			results := CheckContentTypeForSecret.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckContentTypeForSecret.LongID() {
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
