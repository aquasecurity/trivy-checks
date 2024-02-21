package keyvault

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/keyvault"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSpecifyNetworkAcl(t *testing.T) {
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name: "Network ACL default action set to allow",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      trivyTypes.NewTestMetadata(),
							DefaultAction: trivyTypes.String("Allow", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Network ACL default action set to deny",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      trivyTypes.NewTestMetadata(),
							DefaultAction: trivyTypes.String("Deny", trivyTypes.NewTestMetadata()),
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
			results := CheckSpecifyNetworkAcl.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSpecifyNetworkAcl.LongID() {
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
