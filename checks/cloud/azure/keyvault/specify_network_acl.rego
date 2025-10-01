# METADATA
# title: Key vault should have the network acl block specified
# description: |
#   Network ACLs allow you to reduce your exposure to risk by limiting what can access your key vault.
#
#   The default action of the Network ACL should be set to deny for when IPs are not matched. Azure services can be allowed to bypass.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/key-vault/general/network-security
# custom:
#   id: AVD-AZU-0013
#   avd_id: AVD-AZU-0013
#   provider: azure
#   service: keyvault
#   severity: CRITICAL
#   short_code: specify-network-acl
#   recommended_action: Set a network ACL for the key vault
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: keyvault
#             provider: azure
#   examples: checks/cloud/azure/keyvault/specify_network_acl.yaml
package builtin.azure.keyvault.azure0013

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some vault in input.azure.keyvault.vaults
	isManaged(vault)
	not block_access_by_default(vault)
	res := result.new(
		"Vault network ACL does not block access by default.",
		metadata.obj_by_path(vault, ["networkacls", "defaultaction"]),
	)
}

block_access_by_default(vault) := vault.networkacls.defaultaction.value == "Deny"
