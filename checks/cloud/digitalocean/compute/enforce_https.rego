# METADATA
# title: The load balancer forwarding rule is using an insecure protocol as an entrypoint
# description: |
#   Plain HTTP is unencrypted and human-readable. This means that if a malicious actor was to eavesdrop on your connection, they would be able to see all of your data flowing back and forth.
#   You should use HTTPS, which is HTTP over an encrypted (TLS) connection, meaning eavesdroppers cannot read your traffic.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.digitalocean.com/products/networking/load-balancers/
# custom:
#   id: DIG-0002
#   aliases:
#     - AVD-DIG-0002
#     - enforce-https
#   long_id: digitalocean-compute-enforce-https
#   provider: digitalocean
#   service: compute
#   severity: CRITICAL
#   recommended_action: Switch to HTTPS to benefit from TLS security features
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: digitalocean
#   examples: checks/cloud/digitalocean/compute/enforce_https.yaml
package builtin.digitalocean.compute.digitalocean0002

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some lb in input.digitalocean.compute.loadbalancers
	not is_redirect_http_to_https(lb)
	some rule in lb.forwardingrules
	value.is_equal(rule.entryprotocol, "http")
	res := result.new(
		"Load balancer has aforwarding rule which uses HTTP instead of HTTPS.",
		rule.entryprotocol,
	)
}

is_redirect_http_to_https(lb) := lb.redirecthttptohttps.value
