# METADATA
# title: SSH Access Is Not Restricted
# description: |
#   Firewall rules should restrict SSH (TCP/22) access to specific IPs. Open SSH can be a security risk.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall
# custom:
#   id: GCP-0071
#   aliases:
#     - AVD-GCP-0071
#     - ssh-access-is-not-restricted
#   long_id: google-compute-restrict-ssh-access
#   provider: google
#   service: compute
#   severity: MEDIUM
#   recommended_action: |
#     Restrict SSH (TCP port 22) access in firewall rules to known IP addresses or ranges. Avoid open 0.0.0.0/0 access for SSH.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/restrict_ssh_access.yaml
package builtin.google.compute.google0071

import rego.v1

import data.lib.net

deny contains res if {
	some network in input.google.compute.networks
	some rule in network.firewall.ingressrules
	rule.firewallrule.isallow.value
	rule.firewallrule.enforced.value

	# Check if rule allows SSH port (22)
	net.is_tcp_protocol(rule.firewallrule.protocol.value)
	is_ssh_port(rule)

	# Check if rule allows access from public internet
	some source in rule.sourceranges
	net.cidr_allows_all_ips(source.value)

	res := result.new(
		"Firewall rule allows SSH access from the public internet.",
		source,
	)
}

is_ssh_port(rule) if {
	some port in rule.firewallrule.ports
	net.is_port_range_include(port.start.value, port.end.value, net.ssh_port)
}
