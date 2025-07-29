# METADATA
# title: Google Compute Network Using Firewall Rule that Allows All Ports
# description: |
#   Firewall rules should not be wide open to all ports. Lock down rules to only required ports.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#allow
# custom:
#   id: GCP-0072
#   aliases:
#     - AVD-GCP-0072
#     - network-using-firewall-rule-that-allows-all-ports
#   long_id: google-compute-disable-allow-all-ports
#   provider: google
#   service: compute
#   severity: MEDIUM
#   recommended_action: |
#     Modify firewall rules that allow all ports to restrict to only required ports. Use separate rules for specific port ranges as needed, instead of a single overly broad rule.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/disable_allow_all_ports_firewall_rule.yaml
package builtin.google.compute.google0072

import rego.v1

import data.lib.net

deny contains res if {
	some network in input.google.compute.networks
	some rule in network.firewall.ingressrules
	rule.firewallrule.isallow.value
	rule.firewallrule.enforced.value

	# Check if rule allows all ports
	allows_all_ports(rule)

	res := result.new(
		"Firewall rule allows access to all ports.",
		rule,
	)
}

deny contains res if {
	some network in input.google.compute.networks
	some rule in network.firewall.egressrules
	rule.firewallrule.isallow.value
	rule.firewallrule.enforced.value

	# Check if rule allows all ports
	allows_all_ports(rule)

	res := result.new(
		"Firewall rule allows access to all ports.",
		rule,
	)
}

# Rule allows all ports if it covers the entire port range
allows_all_ports(rule) if {
	some port in rule.firewallrule.ports
	port.start.value == 0
	port.end.value == 65535
}

# If no ports are specified, this rule applies to connections through any port.
# See https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#ports-1
allows_all_ports(rule) if {
	not rule.firewallrule.ports
}

# Rule allows all ports if protocol is set to "all" or "-1"
allows_all_ports(rule) if {
	net.protocol(rule.firewallrule.protocol.value) in net.all_protocols
}
