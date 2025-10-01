# METADATA
# title: A firewall rule should not allow unrestricted ingress from any IP address.
# description: |
#   Opening up ports to allow connections from the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
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
#   examples: checks/cloud/digitalocean/compute/no_public_ingress.yaml
package builtin.digitalocean.compute.digitalocean0001

import rego.v1

import data.lib.net

deny contains res if {
	some address in input.digitalocean.compute.firewalls[_].inboundrules[_].sourceaddresses
	net.cidr_allows_all_ips(address.value)
	res := result.new(
		"Firewall rule allows unrestricted ingress from any IP address.",
		address,
	)
}
