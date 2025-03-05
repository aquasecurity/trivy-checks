# METADATA
# title: A firewall rule should not allow unrestricted egress to any IP address.
# description: |
#   Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
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
#   examples: checks/cloud/digitalocean/compute/no_public_egress.yaml
package builtin.digitalocean.compute.digitalocean0003

import rego.v1

import data.lib.net

deny contains res if {
	some address in input.digitalocean.compute.firewalls[_].outboundrules[_].destinationaddresses
	net.cidr_allows_all_ips(address.value)
	res := result.new(
		"Firewall rule allows egress traffic to any IP address.",
		address,
	)
}
