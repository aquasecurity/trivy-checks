# METADATA
# title: A security group should not allow unrestricted ingress to the RDP port from any IP address.
# description: |
#   RDP access can be configured on either the network security group or in the network security group rule.
#   RDP access should not be permitted from the internet (*, 0.0.0.0, /0, internet, any). Consider using the Azure Bastion Service.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/bastion/tutorial-create-host-portal
# custom:
#   id: AVD-AZU-0048
#   avd_id: AVD-AZU-0048
#   provider: azure
#   service: network
#   severity: CRITICAL
#   short_code: disable-rdp-from-internet
#   recommended_action: Block RDP port from internet
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: azure
#   examples: checks/cloud/azure/network/disable_rdp_from_internet.yaml
package builtin.azure.network.azure0048

import rego.v1

import data.lib.net

deny contains res if {
	some group in input.azure.network.securitygroups
	some rule in group.rules
	rule.allow.value
	not rule.outbound.value
	lower(rule.protocol.value) != "icmp"
	some ports in rule.destinationports
	port_range_includes(ports.start, ports.end, 3389)
	some ip in rule.sourceaddresses
	net.cidr_allows_all_ips(ip.value)
	res := result.new(
		"Security group rule allows unrestricted ingress to RDP port from any IP address.",
		ip,
	)
}

port_range_includes(from, to, port) if {
	from.value <= port
	port <= to.value
}
