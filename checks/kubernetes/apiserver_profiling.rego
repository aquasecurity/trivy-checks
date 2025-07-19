# METADATA
# title: "Ensure that the --profiling argument is set to false"
# description: "Disable profiling, if not needed."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0018
#   aliases:
#     - AVD-KCV-0018
#     - KCV0018
#     - ensure-profiling-argument-is-set-to-false
#   long_id: kubernetes-ensure-profiling-argument-is-set-to-false
#   severity: LOW
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the below parameter."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0018

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--profiling=false")
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--profiling=false")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --profiling argument is set to false"
	res := result.new(msg, container)
}
