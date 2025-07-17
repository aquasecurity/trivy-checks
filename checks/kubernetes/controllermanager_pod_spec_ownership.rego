# METADATA
# title: "Ensure that the controller manager pod specification file ownership is set to root:root"
# description: "Ensure that the controller manager pod specification file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0051
#   aliases:
#     - AVD-KCV-0051
#     - KCV0051
#     - ensure-controller-manager-pod-specification-ownership-set
#   severity: HIGH
#   short_code: ensure-controller-manager-pod-specification-ownership-set-root:root.
#   recommended_action: "Change the controller manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0051

import rego.v1

validate_spec_ownership(sp) := {"kubeControllerManagerSpecFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.kubeControllerManagerSpecFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_spec_ownership(input)
	msg := "Ensure that the controller manager pod specification file ownership is set to root:root"
	res := result.new(msg, output)
}
