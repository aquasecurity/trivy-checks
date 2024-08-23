# METADATA
# title: An outbound network security rule allows traffic to /0.
# description: |
#   Network security rules should not use very broad subnets.
#   Where possible, segments should be broken into smaller subnets.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/security/fundamentals/network-best-practices
# custom:
#   id: AVD-AZU-0051
#   avd_id: AVD-AZU-0051
#   provider: azure
#   service: network
#   severity: CRITICAL
#   short_code: no-public-egress
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
#     good_examples: checks/cloud/azure/network/no_public_egress.tf.go
#     bad_examples: checks/cloud/azure/network/no_public_egress.tf.go
package builtin.azure.network.azure0051

import rego.v1

deny contains res if {
	some group in input.azure.network.securitygroups
	some rule in group.rules
	rule.outbound.value
	rule.allow.value
	some addr in rule.destinationaddresses
	cidr.is_public(addr.value)
	res := result.new("Security group rule allows egress to public internet.", addr)
}
