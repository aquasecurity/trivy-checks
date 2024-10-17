# METADATA
# title: The firewall has an outbound rule with open access
# description: |
#   Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/
# custom:
#   id: AVD-DIG-0003
#   avd_id: AVD-DIG-0003
#   provider: digitalocean
#   service: compute
#   severity: CRITICAL
#   short_code: no-public-egress
#   recommended_action: Set a more restrictive cidr range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: digitalocean
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/firewall
#     good_examples: checks/cloud/digitalocean/compute/no_public_egress.yaml
#     bad_examples: checks/cloud/digitalocean/compute/no_public_egress.yaml
package builtin.digitalocean.compute.digitalocean0003

import rego.v1

deny contains res if {
	some address in input.digitalocean.compute.firewalls[_].outboundrules[_].destinationaddresses
	cidr.is_public(address.value)
	cidr.count_addresses(address.value) > 1
	res := result.new(
		"Egress rule allows access to multiple public addresses.",
		address,
	)
}
