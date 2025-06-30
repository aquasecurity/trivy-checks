# METADATA
# title: Trusted Microsoft Services should have bypass access to Storage accounts
# description: |
#   Some Microsoft services that interact with storage accounts operate from networks that can't be granted access through network rules.
#   To help this type of service work as intended, allow the set of trusted Microsoft services to bypass the network rules
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security#trusted-microsoft-services
# custom:
#   id: AVD-AZU-0010
#   avd_id: AVD-AZU-0010
#   provider: azure
#   service: storage
#   severity: HIGH
#   short_code: allow-microsoft-service-bypass
#   recommended_action: Allow Trusted Microsoft Services to bypass
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/allow_microsoft_service_bypass.yaml
package builtin.azure.storage.azure0010

import rego.v1

deny contains res if {
	some rule in input.azure.storage.accounts[_].networkrules
	not has_bypass(rule)
	res := result.new(
		"Network rules do not allow bypass for Microsoft Services.",
		rule,
	)
}

has_bypass(rule) if {
	some bypass in rule.bypass
	bypass.value == "AzureServices"
}
