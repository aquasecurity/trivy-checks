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
#   id: AVD-DIG-0002
#   avd_id: AVD-DIG-0002
#   provider: digitalocean
#   service: compute
#   severity: CRITICAL
#   short_code: enforce-https
#   recommended_action: Switch to HTTPS to benefit from TLS security features
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: compute
#             provider: digitalocean
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/digitalocean/digitalocean/latest/docs/resources/loadbalancer
#     good_examples: checks/cloud/digitalocean/compute/enforce_https.yaml
#     bad_examples: checks/cloud/digitalocean/compute/enforce_https.yaml
package builtin.digitalocean.compute.digitalocean0002

import rego.v1

deny contains res if {
	some lb in input.digitalocean.compute.loadbalancers
	not is_redirect_http_to_https(lb)
	some rule in lb.forwardingrules
	rule.entryprotocol.value == "http"
	res := result.new(
		"Load balancer has aforwarding rule which uses HTTP instead of HTTPS.",
		rule.entryprotocol,
	)
}

is_redirect_http_to_https(lb) := lb.redirecthttptohttps.value
