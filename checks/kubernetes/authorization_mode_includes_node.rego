# METADATA
# title: "Ensure that the --authorization-mode argument includes Node"
# description: "Restrict kubelet nodes to reading only objects associated with them."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0008
#   aliases:
#     - AVD-KCV-0008
#     - KCV0008
#     - ensure-authorization-mode-argument-includes-node
#   long_id: kubernetes-ensure-authorization-mode-argument-includes-node
#   severity: LOW
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --authorization-mode parameter to a value that includes Node."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0008

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--authorization-mode")
	some i
	output := regex.find_all_string_submatch_n(`--authorization-mode=([^\s]+)`, container.command[i], -1)
	regex.match("Node", output[0][1])
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--authorization-mode")
	some i
	output := regex.find_all_string_submatch_n(`--authorization-mode=([^\s]+)`, container.args[i], -1)
	regex.match("Node", output[0][1])
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --authorization-mode argument includes Node"
	res := result.new(msg, container)
}
