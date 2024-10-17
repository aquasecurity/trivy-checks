# METADATA
# title: SSH access should not be accessible from the Internet, should be blocked on port 22
# description: |
#   SSH access can be configured on either the network security group or in the network security group rule.
#   SSH access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any)
# scope: package
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: AVD-AZU-0050
#   avd_id: AVD-AZU-0050
#   provider: azure
#   service: network
#   severity: CRITICAL
#   short_code: ssh-blocked-from-internet
#   recommended_action: Block port 22 access from the internet
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges
#     good_examples: checks/cloud/azure/network/ssh_blocked_from_internet.yaml
#     bad_examples: checks/cloud/azure/network/ssh_blocked_from_internet.yaml
package builtin.azure.network.azure0050

import rego.v1

deny contains res if {
	some group in input.azure.network.securitygroups
	some rule in group.rules
	rule.allow.value
	not rule.outbound.value
	lower(rule.protocol.value) != "icmp"
	some ports in rule.destinationports
	port_range_includes(ports.start, ports.end, 22)
	some ip in rule.sourceaddresses
	cidr.is_public(ip.value)
	cidr.count_addresses(ip.value) > 1
	res := result.new(
		"Security group rule allows ingress to SSH port from multiple public internet addresses.",
		ip,
	)
}

port_range_includes(from, to, port) if {
	from.value <= port
	port <= to.value
}
