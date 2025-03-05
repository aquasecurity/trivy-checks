# METADATA
# title: A security group rule should not allow unrestricted ingress from any IP address.
# description: |
#   Opening up ports to allow connections from the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
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
#   examples: checks/cloud/azure/network/no_public_ingress.yaml
package builtin.azure.network.azure0047

import rego.v1

import data.lib.net

deny contains res if {
	some group in input.azure.network.securitygroups
	some rule in group.rules
	not rule.outbound.value
	rule.allow.value
	some addr in rule.sourceaddresses
	net.cidr_allows_all_ips(addr.value)
	res := result.new("Security group rule allows unrestricted ingress from any IP address.", addr)
}
