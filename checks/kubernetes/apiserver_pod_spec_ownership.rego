# METADATA
# title: "Ensure that the API server pod specification file ownership is set to root:root"
# description: "Ensure that the API server pod specification file ownership is set to root:root."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0049
#   aliases:
#     - AVD-KCV-0049
#     - KCV0049
#     - ensure-api-server-pod-specification-ownership-set-root:root.
#   long_id: kubernetes-ensure-api-server-pod-specification-ownership-set-root:root.
#   severity: HIGH
#   recommended_action: "Change the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml ownership to root:root"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0049

import rego.v1

validate_spec_ownership(sp) := {"kubeAPIServerSpecFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.kubeAPIServerSpecFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_spec_ownership(input)
	msg := "Ensure that the API server pod specification file ownership is set to root:root"
	res := result.new(msg, output)
}
