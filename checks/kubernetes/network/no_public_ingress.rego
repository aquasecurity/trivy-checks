# METADATA
# title: Public ingress should not be allowed via network policies
# description: You should not expose infrastructure to the public internet except where explicitly required
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
#   terraform:
#     good_examples: checks/kubernetes/network/no_public_ingress.yaml
#     links:
#       - https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs/resources/network_policy#spec.ingress.from.ip_block.cidr
package builtin.kube.network.kube0001

import rego.v1

deny contains res if {
	some policy in input.kubernetes.networkpolicies
	isManaged(policy)
	some source in policy.spec.ingress.sourcecidrs
	cidr.is_public(source.value)
	res := result.new(
		"Network policy allows ingress from the public internet.",
		source,
	)
}
