# METADATA
# title: Ensure that the expiration date is set on all keys
# description: |
#   Expiration Date is an optional Key Vault Key behavior and is not set by default.
#
#   Set when the resource will be become inactive.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/powershell/module/az.keyvault/update-azkeyvaultkey?view=azps-5.8.0#example-1--modify-a-key-to-enable-it--and-set-the-expiration-date-and-tags
# custom:
#   id: AVD-AZU-0014
#   avd_id: AVD-AZU-0014
#   provider: azure
#   service: keyvault
#   severity: MEDIUM
#   short_code: ensure-key-expiry
#   recommended_action: Set an expiration date on the vault key
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: keyvault
#             provider: azure
#   examples: checks/cloud/azure/keyvault/ensure_key_expiry.yaml
package builtin.azure.keyvault.azure0014

import rego.v1

import data.lib.datetime

deny contains res if {
	some vault in input.azure.keyvault.vaults
	some key in vault.keys
	not key_has_expiry_date(key)
	res := result.new(
		"Key should have an expiry date specified.",
		object.get(key, "expirydate", key),
	)
}

key_has_expiry_date(key) := datetime.is_valid(key.expirydate.value)
