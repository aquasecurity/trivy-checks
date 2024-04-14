# METADATA
# title: "Ensure that the --authorization-mode argument includes Node"
# description: "Restrict kubelet nodes to reading only objects associated with them."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0008
#   avd_id: AVD-KCV-0008
#   severity: LOW
#   short_code: ensure-authorization-mode-argument-includes-node
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --authorization-mode parameter to a value that includes Node."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0008

import data.lib.kubernetes

check_flag(container) {
	kubernetes.command_has_flag(container.command, "--authorization-mode")
	some i
	output := regex.find_all_string_submatch_n(`--authorization-mode=([^\s]+)`, container.command[i], -1)
	regex.match("Node", output[0][1])
}

check_flag(container) {
	kubernetes.command_has_flag(container.args, "--authorization-mode")
	some i
	output := regex.find_all_string_submatch_n(`--authorization-mode=([^\s]+)`, container.args[i], -1)
	regex.match("Node", output[0][1])
}

deny[res] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --authorization-mode argument includes Node"
	res := result.new(msg, container)
}
