# METADATA
# title: Google Compute Network Using Firewall Rule that Allows Large Port Range
# description: |
#   Firewall rules allowing broad port ranges can be risky. Ensure rules are as specific as possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#allow
# custom:
#   id: GCP-0074
#   aliases:
#     - compute-network-using-firewall-rule-that-allows-large-port-range
#     - AVD-GCP-0074
#   long_id: google-compute-disable-port-range-rule
#   provider: google
#   service: compute
#   severity: LOW
#   recommended_action: |
#     Limit firewall rules to necessary port ranges only. If a wide range is specified, consider splitting into smaller ranges or specific ports needed for your application.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/disable_port_range_rule.yaml
package builtin.google.compute.google0074

import rego.v1

import data.gcp0074.max_port_range_size as custom_max_range

# Maximum allowed port range size - ports above this threshold will be flagged
default_max_port_range_size := 30
max_port_range_size := custom_max_range if {
	custom_max_range >= 0
} else := default_max_port_range_size

deny contains res if {
	some network in input.google.compute.networks
	some rule in network.firewall.ingressrules
	some port in rule.firewallrule.ports
	port_range_size := port.end.value - port.start.value
	port_range_size > max_port_range_size

	res := result.new(
		sprintf("Firewall rule allows a large port range (%d ports, max allowed: %d).", [port_range_size, max_port_range_size]),
		port,
	)
}
