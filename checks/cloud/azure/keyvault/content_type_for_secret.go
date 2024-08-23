package keyvault

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckContentTypeForSecret = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0015",
		Provider:   providers.AzureProvider,
		Service:    "keyvault",
		ShortCode:  "content-type-for-secret",
		Summary:    "Key vault Secret should have a content type set",
		Impact:     "The secret's type is unclear without a content type",
		Resolution: "Provide content type for secrets to aid interpretation on retrieval",
		Explanation: `Content Type is an optional Key Vault Secret behavior and is not enabled by default.

Clients may specify the content type of a secret to assist in interpreting the secret data when it's retrieved. The maximum length of this field is 255 characters. There are no pre-defined values. The suggested usage is as a hint for interpreting the secret data.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformContentTypeForSecretGoodExamples,
			BadExamples:         terraformContentTypeForSecretBadExamples,
			Links:               terraformContentTypeForSecretLinks,
			RemediationMarkdown: terraformContentTypeForSecretRemediationMarkdown,
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, vault := range s.Azure.KeyVault.Vaults {
			for _, secret := range vault.Secrets {
				if secret.ContentType.IsEmpty() {
					results.Add(
						"Secret does not have a content-type specified.",
						secret.ContentType,
					)
				} else {
					results.AddPassed(&secret)
				}
			}
		}
		return
	},
)
