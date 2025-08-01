# METADATA
# title: "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate"
# description: "Activate garbage collector on pod termination, as appropriate."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0033
#   aliases:
#     - AVD-KCV-0033
#     - KCV0033
#     - ensure-terminated-pod-gc-threshold-argument-is-set-as-appropriate
#   long_id: kubernetes-ensure-terminated-pod-gc-threshold-argument-is-set-as-appropriate
#   severity: LOW
#   recommended_action: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --terminated-pod-gc-threshold to an appropriate threshold."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0033

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--terminated-pod-gc-threshold")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--terminated-pod-gc-threshold")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_controllermanager(container)
	not checkFlag(container)
	msg := "Ensure that the --terminated-pod-gc-threshold argument is set as appropriate"
	res := result.new(msg, container)
}
