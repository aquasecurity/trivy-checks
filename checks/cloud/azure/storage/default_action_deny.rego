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
#   long_id: azure-storage-default-action-deny
#   aliases:
#     - AVD-AZU-0012
#     - default-action-deny
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
		"A network rule is configured to allow access.",
		rule.allowbydefault,
	)
}

deny contains res if {
	some account in input.azure.storage.accounts
	isManaged(account)
	not has_networks(account)

	# Default 'Allow' rule is applied when no network rules are defined.
	# See https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security?tabs=azure-portal#change-the-default-network-access-rule
	res := result.new(
		"No network rules defined and default action allows access.",
		account,
	)
}

has_networks(account) if count(account.networkrules) > 0
