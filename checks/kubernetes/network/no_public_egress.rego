# METADATA
# title: Public egress should not be allowed via network policies
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
#   terraform:
#     good_examples: checks/kubernetes/network/no_public_egress.yaml
#     links:
#       - https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/network_policy#spec.egress.to.ip_block.cidr
package builtin.kube.network.kube0002

import rego.v1

deny contains res if {
	some policy in input.kubernetes.networkpolicies
	isManaged(policy)
	some dest in policy.spec.egress.destinationcidrs
	cidr.is_public(dest.value)
	res := result.new(
		"Network policy allows egress to the public internet.",
		dest,
	)
}
