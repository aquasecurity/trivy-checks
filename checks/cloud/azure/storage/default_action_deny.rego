# METADATA
# title: The default action on Storage account network rules should be set to deny
# description: |
#   The default_action for network rules should come into effect when no other rules are matched.
#   The default action should be set to Deny.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/firewall/rule-processing
# custom:
#   id: AZU-0012
#   aliases:
#     - AVD-AZU-0012
#     - default-action-deny
#   long_id: azure-storage-default-action-deny
#   provider: azure
#   service: storage
#   severity: CRITICAL
#   recommended_action: Set network rules to deny
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: storage
#             provider: azure
#   examples: checks/cloud/azure/storage/default_action_deny.yaml
package builtin.azure.storage.azure0012

import rego.v1

deny contains res if {
	some rule in input.azure.storage.accounts[_].networkrules
	rule.allowbydefault.value
	res := result.new(
		"Network rules allow access by default.",
		rule.allowbydefault,
	)
}
