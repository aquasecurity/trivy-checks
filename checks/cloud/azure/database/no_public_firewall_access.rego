# METADATA
# title: Ensure database firewalls do not permit public access
# description: |
#   Azure services can be allowed access through the firewall using a start and end IP address of 0.0.0.0. No other end ip address should be combined with a start of 0.0.0.0
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/rest/api/sql/2021-02-01-preview/firewall-rules/create-or-update
# custom:
#   id: AVD-AZU-0029
#   avd_id: AVD-AZU-0029
#   provider: azure
#   service: database
#   severity: HIGH
#   short_code: no-public-firewall-access
#   recommended_action: Don't use wide ip ranges for the sql firewall
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_firewall_rule#end_ip_address
#     good_examples: checks/cloud/azure/database/no_public_firewall_access.yaml
#     bad_examples: checks/cloud/azure/database/no_public_firewall_access.yaml
package builtin.azure.database.azure0029

import rego.v1

import data.lib.azure.database

deny contains res if {
	some server in database.all_servers
	some rule in server.firewallrules
	not allowing_azure_services(rule)
	rule.startip.value != rule.endip.value
	is_public_rule(rule)
	res := result.new(
		"Firewall rule allows public internet access to a database server.",
		rule,
	)
}

is_public_rule(rule) if cidr.is_public(rule.startip.value)

is_public_rule(rule) if cidr.is_public(rule.endip.value)

allowing_azure_services(rule) if {
	rule.startip.value == "0.0.0.0"
	rule.endip.value == "0.0.0.0"
}
