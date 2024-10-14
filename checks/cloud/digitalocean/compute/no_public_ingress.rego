# METADATA
# title: The firewall has an inbound rule with open access
# description: |
#   Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/
# custom:
#   id: AVD-DIG-0001
#   avd_id: AVD-DIG-0001
#   provider: digitalocean
#   service: compute
#   severity: CRITICAL
#   short_code: no-public-ingress
#   recommended_action: Set a more restrictive CIRDR range
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: digitalocean
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/firewall
#     good_examples: checks/cloud/digitalocean/compute/no_public_ingress.yaml
#     bad_examples: checks/cloud/digitalocean/compute/no_public_ingress.yaml
package builtin.digitalocean.compute.digitalocean0001

import rego.v1

deny contains res if {
	some address in input.digitalocean.compute.firewalls[_].inboundrules[_].sourceaddresses
	cidr.is_public(address.value)
	cidr.count_addresses(address.value) > 1
	res := result.new(
		"Ingress rule allows access from multiple public addresses.",
		address,
	)
}
