# METADATA
# title: "Ensure that the --authorization-mode argument includes RBAC"
# description: "Turn on Role Based Access Control."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0009
#   aliases:
#     - AVD-KCV-0009
#     - KCV0009
#     - ensure-authorization-mode-argument-includes-rbac
#   long_id: kubernetes-ensure-authorization-mode-argument-includes-rbac
#   severity: LOW
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --authorization-mode parameter to a value that includes RBAC."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0009

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--authorization-mode")
	some i
	output := regex.find_all_string_submatch_n(`--authorization-mode=([^\s]+)`, container.command[i], -1)
	regex.match("RBAC", output[0][1])
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--authorization-mode")
	some i
	output := regex.find_all_string_submatch_n(`--authorization-mode=([^\s]+)`, container.args[i], -1)
	regex.match("RBAC", output[0][1])
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --authorization-mode argument includes RBAC"
	res := result.new(msg, container)
}
