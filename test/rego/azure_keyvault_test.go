package test

import (
	"time"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/keyvault"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(azureKeyVaultTestCases)
}

var azureKeyVaultTestCases = testCases{
	"AVD-AZU-0015": {
		{
			name: "Key vault secret content-type not specified",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
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
			}}},
			expected: true,
		},
		{
			name: "Key vault secret content-type specified",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
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
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0014": {
		{
			name: "Key vault key expiration date not set",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
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
			}}},
			expected: true,
		},
		{
			name: "Key vault key expiration date specified",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
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
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0017": {
		{
			name: "Key vault secret expiration date not set",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:   trivyTypes.NewTestMetadata(),
								ExpiryDate: trivyTypes.Time(time.Time{}, trivyTypes.NewTestMetadata().GetMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Key vault secret expiration date specified",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:   trivyTypes.NewTestMetadata(),
								ExpiryDate: trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata().GetMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0016": {
		{
			name: "Keyvault purge protection disabled",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						EnablePurgeProtection:   trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: trivyTypes.Int(30, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Keyvault purge protection enabled but soft delete retention period set to 3 days",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						EnablePurgeProtection:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: trivyTypes.Int(3, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Keyvault purge protection enabled and soft delete retention period set to 30 days",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						EnablePurgeProtection:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: trivyTypes.Int(30, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0013": {
		{
			name: "Network ACL default action set to allow",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      trivyTypes.NewTestMetadata(),
							DefaultAction: trivyTypes.String("Allow", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Network ACL default action set to deny",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      trivyTypes.NewTestMetadata(),
							DefaultAction: trivyTypes.String("Deny", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
