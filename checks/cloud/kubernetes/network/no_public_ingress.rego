# METADATA
# title: A network policy should not allow unrestricted ingress from any IP address.
# description: |
#   Opening up ports to allow connections from the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.
# scope: package
# schemas:
# - input: schema["cloud"]
# custom:
#   id: AVD-KUBE-0001
#   avd_id: AVD-KUBE-0001
#   provider: kubernetes
#   service: network
#   severity: HIGH
#   short_code: no-public-ingress
#   recommended_action: Remove public access except where explicitly required
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#           - provider: kubernetes
#             service: networkpolicies
#   examples: checks/cloud/kubernetes/network/no_public_ingress.yaml
package builtin.kube.network.kube0001

import rego.v1

import data.lib.net

deny contains res if {
	some policy in input.kubernetes.networkpolicies
	isManaged(policy)
	some source in policy.spec.ingress.sourcecidrs
	net.cidr_allows_all_ips(source.value)
	res := result.new(
		"Network policy allows unrestricted ingress from any IP address.",
		source,
	)
}
