# METADATA
# title: Key Vault Secret should have an expiration date set
# description: |
#   Expiration Date is an optional Key Vault Secret behavior and is not set by default.
#
#   Set when the resource will be become inactive.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets
# custom:
#   id: AVD-AZU-0017
#   avd_id: AVD-AZU-0017
#   provider: azure
#   service: keyvault
#   severity: LOW
#   short_code: ensure-secret-expiry
#   recommended_action: Set an expiry for secrets
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: keyvault
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#expiration_date
#     good_examples: checks/cloud/azure/keyvault/ensure_secret_expiry.yaml
#     bad_examples: checks/cloud/azure/keyvault/ensure_secret_expiry.yaml
package builtin.azure.keyvault.azure0017

import rego.v1

import data.lib.datetime

deny contains res if {
	some vault in input.azure.keyvault.vaults
	some secret in vault.secrets

	not secret_has_expiry_date(secret)
	res := result.new(
		"Secret should have an expiry date specified.",
		object.get(secret, "expirydate", secret),
	)
}

secret_has_expiry_date(secret) := datetime.is_valid(secret.expirydate.value)
