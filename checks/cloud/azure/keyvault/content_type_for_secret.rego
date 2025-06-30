# METADATA
# title: Key vault Secret should have a content type set
# description: |
#   Content Type is an optional Key Vault Secret behavior and is not enabled by default.
#
#   Clients may specify the content type of a secret to assist in interpreting the secret data when it's retrieved. The maximum length of this field is 255 characters. There are no pre-defined values. The suggested usage is as a hint for interpreting the secret data.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/key-vault/secrets/about-secrets
# custom:
#   id: AVD-AZU-0015
#   avd_id: AVD-AZU-0015
#   provider: azure
#   service: keyvault
#   severity: LOW
#   short_code: content-type-for-secret
#   recommended_action: Provide content type for secrets to aid interpretation on retrieval
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: keyvault
#             provider: azure
#   examples: checks/cloud/azure/keyvault/content_type_for_secret.yaml
package builtin.azure.keyvault.azure0015

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some vault in input.azure.keyvault.vaults
	some secret in vault.secrets
	secret_without_content_type(secret)
	res := result.new(
		"Secret does not have a content-type specified.",
		object.get(secret, "contenttype", secret),
	)
}

secret_without_content_type(secret) if value.is_empty(secret.contenttype)

secret_without_content_type(secret) if not secret.contenttype
