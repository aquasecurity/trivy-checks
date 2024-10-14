# METADATA
# title: An inbound network security rule allows traffic from /0.
# description: |
#   Network security rules should not use very broad subnets.
#   Where possible, segments should be broken into smaller subnets.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices
# custom:
#   id: AVD-AZU-0047
#   avd_id: AVD-AZU-0047
#   provider: azure
#   service: network
#   severity: CRITICAL
#   short_code: no-public-ingress
#   recommended_action: Set a more restrictive cidr range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule
#     good_examples: checks/cloud/azure/network/no_public_ingress.yaml
#     bad_examples: checks/cloud/azure/network/no_public_ingress.yaml
package builtin.azure.network.azure0047

import rego.v1

deny contains res if {
	some group in input.azure.network.securitygroups
	some rule in group.rules
	not rule.outbound.value
	rule.allow.value
	some addr in rule.sourceaddresses
	cidr.is_public(addr.value)
	cidr.count_addresses(addr.value) > 1
	res := result.new("Security group rule allows ingress from public internet.", addr)
}
