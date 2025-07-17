# METADATA
# title: "Ensure that the scheduler pod specification file ownership is set to root:root"
# description: "Ensure that the scheduler pod specification file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0053
#   aliases:
#     - AVD-KCV-0053
#     - KCV0053
#     - ensure-scheduler-pod-specification-ownership-set
#   severity: HIGH
#   short_code: ensure-scheduler-pod-specification-ownership-set-root:root.
#   recommended_action: "Change the scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0053

import rego.v1

validate_spec_ownership(sp) := {"kubeSchedulerSpecFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.kubeSchedulerSpecFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_spec_ownership(input)
	msg := "Ensure that the scheduler pod specification file ownership is set to root:root"
	res := result.new(msg, output)
}
