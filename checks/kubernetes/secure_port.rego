# METADATA
# title: "Ensure that the --secure-port argument is not set to 0"
# description: "Do not disable the secure port."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0017
#   aliases:
#     - AVD-KCV-0017
#     - KCV0017
#     - ensure-secure-port-argument-is-not-set-to-0
#   long_id: kubernetes-ensure-secure-port-argument-is-not-set-to-0
#   severity: LOW
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and either remove the --secure-port parameter or set it to a different (non-zero) desired port."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0017

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--secure-port=0")
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--secure-port=0")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	check_flag(container)
	msg := "Ensure that the --secure-port argument is not set to 0"
	res := result.new(msg, container)
}
