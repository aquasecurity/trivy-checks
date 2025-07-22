# METADATA
# title: "Ensure that the container network interface file ownership is set to root:root"
# description: "Ensure that the container network interface file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0057
#   aliases:
#     - AVD-KCV-0057
#     - KCV0057
#     - ensure-container-network-interface-ownership-set
#   severity: HIGH
#   short_code: ensure-container-network-interface-ownership-set-root:root.
#   recommended_action: "Change the container network interface file path/to/cni/files ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0057

import rego.v1

validate_spec_ownership(sp) := {"containerNetworkInterfaceFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.containerNetworkInterfaceFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_spec_ownership(input)
	msg := "Ensure that the container network interface file ownership is set to root:root"
	res := result.new(msg, output)
}
