# METADATA
# title: A network policy should not allow unrestricted egress to any IP address.
# description: You should not expose infrastructure to the public internet except where explicitly required
# scope: package
# schemas:
# - input: schema["cloud"]
# custom:
#   id: AVD-KUBE-0002
#   avd_id: AVD-KUBE-0002
#   provider: kubernetes
#   service: network
#   severity: HIGH
#   short_code: no-public-egress
#   recommended_action: Remove public access except where explicitly required
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#           - provider: kubernetes
#             service: networkpolicies
#   examples: checks/cloud/kubernetes/network/no_public_egress.yaml
package builtin.kube.network.kube0002

import rego.v1

import data.lib.net

deny contains res if {
	some policy in input.kubernetes.networkpolicies
	isManaged(policy)
	some dest in policy.spec.egress.destinationcidrs
	net.cidr_allows_all_ips(dest.value)
	res := result.new(
		"Network policy allows unrestricted egress to any IP address.",
		dest,
	)
}
