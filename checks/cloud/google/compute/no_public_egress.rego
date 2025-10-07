# METADATA
# title: A firewall rule should not allow unrestricted egress to any IP address.
# description: |
#   Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/vpc/docs/using-firewalls
# custom:
#   id: AVD-GCP-0035
#   avd_id: AVD-GCP-0035
#   provider: google
#   service: compute
#   severity: CRITICAL
#   short_code: no-public-egress
#   recommended_action: Set a more restrictive cidr range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   examples: checks/cloud/google/compute/no_public_egress.yaml
package builtin.google.compute.google0035

import rego.v1

import data.lib.net

deny contains res if {
	some network in input.google.compute.networks
	some rule in network.firewall.egressrules
	rule.firewallrule.isallow.value
	rule.firewallrule.enforced.value
	some destination in rule.destinationranges
	net.cidr_allows_all_ips(destination.value)
	res := result.new(
		"Firewall rule allows unrestricted egress to any IP address.",
		destination,
	)
}
