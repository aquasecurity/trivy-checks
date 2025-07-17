# METADATA
# title: Key vault should have purge protection enabled
# description: |
#   Purge protection is an optional Key Vault behavior and is not enabled by default.
#
#   Purge protection can only be enabled once soft-delete is enabled. It can be turned on via CLI or PowerShell.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview#purge-protection
# custom:
#   id: AVD-AZU-0016
#   avd_id: AVD-AZU-0016
#   provider: azure
#   service: keyvault
#   severity: MEDIUM
#   short_code: no-purge
#   recommended_action: Enable purge protection for key vaults
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: keyvault
#             provider: azure
#   examples: checks/cloud/azure/keyvault/no_purge.yaml
package builtin.azure.keyvault.azure0016

import rego.v1

deny contains res if {
	some vault in input.azure.keyvault.vaults
	isManaged(vault)
	not vault.enablepurgeprotection.value
	res := result.new(
		"Vault does not have purge protection enabled.",
		object.get(vault, "enablepurgeprotection", vault),
	)
}

deny contains res if {
	some vault in input.azure.keyvault.vaults
	isManaged(vault)
	vault.enablepurgeprotection.value
	not is_valid_soft_delete_retention_days(vault)
	res := result.new(
		"Resource should have soft_delete_retention_days set between 7 and 90 days in order to enable purge protection.",
		object.get(vault, "softdeleteretentiondays", vault),
	)
}

is_valid_soft_delete_retention_days(vault) if {
	vault.softdeleteretentiondays.value >= 7
	vault.softdeleteretentiondays.value <= 90
}
