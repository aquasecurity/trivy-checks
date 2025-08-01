# METADATA
# title: An outdated SSL policy is in use by a load balancer.
# description: |
#   You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/service/lb_l4.htm
# custom:
#   id: NIF-0020
#   aliases:
#     - AVD-NIF-0020
#     - use-secure-tls-policy
#   long_id: nifcloud-network-use-secure-tls-policy
#   provider: nifcloud
#   service: network
#   severity: CRITICAL
#   recommended_action: Use a more recent TLS/SSL policy for the load balancer
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/network/use_secure_tls_policy.yaml
package builtin.nifcloud.network.nifcloud0020

import rego.v1

outdated_sslpolicies := {
	"",
	"1",
	"Standard Ciphers A ver1",
	"2",
	"Standard Ciphers B ver1",
	"3",
	"Standard Ciphers C ver1",
	"5",
	"Ats Ciphers A ver1",
	"8",
	"Ats Ciphers D ver1",
}

deny contains res if {
	some lb in input.nifcloud.network.loadbalancers
	some listener in lb.listeners
	listener.protocol.value == "HTTPS"
	listener.tlspolicy.value in outdated_sslpolicies
	res := result.new("Listener uses an outdated TLS policy.", listener.tlspolicy)
}
