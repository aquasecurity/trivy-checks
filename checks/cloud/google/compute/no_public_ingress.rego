# METADATA
# title: An inbound firewall rule allows traffic from /0.
# description: |
#   Network security rules should not use very broad subnets.
#   Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/vpc/docs/using-firewalls
# custom:
#   id: AVD-GCP-0027
#   avd_id: AVD-GCP-0027
#   provider: google
#   service: compute
#   severity: CRITICAL
#   short_code: no-public-ingress
#   recommended_action: Set a more restrictive cidr range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall#source_ranges
#       - https://www.terraform.io/docs/providers/google/r/compute_firewall.html
#     good_examples: checks/cloud/google/compute/no_public_ingress.yaml
#     bad_examples: checks/cloud/google/compute/no_public_ingress.yaml
package builtin.google.compute.google0027

import rego.v1

deny contains res if {
	some network in input.google.compute.networks
	count(object.get(network.firewall, "sourcetags", [])) == 0
	count(object.get(network.firewall, "targettags", [])) == 0

	some rule in network.firewall.ingressrules
	rule.firewallrule.isallow.value
	rule.firewallrule.enforced.value
	some source in rule.sourceranges
	cidr.is_public(source.value)
	cidr.count_addresses(source.value) > 1
	res := result.new(
		"Firewall rule allows ingress traffic from multiple addresses on the public internet.",
		source,
	)
}
