# METADATA
# title: An outbound firewall rule allows traffic to /0.
# description: |
#   Network security rules should not use very broad subnets.
#   Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.
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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall
#     good_examples: checks/cloud/google/compute/no_public_egress.yaml
#     bad_examples: checks/cloud/google/compute/no_public_egress.yaml
package builtin.google.compute.google0035

import rego.v1

deny contains res if {
	some network in input.google.compute.networks
	some rule in network.firewall.egressrules
	rule.firewallrule.isallow.value
	rule.firewallrule.enforced.value
	some destination in rule.destinationranges
	cidr.is_public(destination.value)
	cidr.count_addresses(destination.value) > 1
	res := result.new(
		"Firewall rule allows egress traffic to multiple addresses on the public internet.",
		destination,
	)
}
