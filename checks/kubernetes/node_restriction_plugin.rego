# METADATA
# title: "Ensure that the admission control plugin NodeRestriction is set"
# description: "Limit the Node and Pod objects that a kubelet could modify."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0016
#   avd_id: AVD-KCV-0016
#   severity: LOW
#   short_code: ensure-admission-control-plugin-node-restriction-is-set
#   recommended_action: "Follow the Kubernetes documentation and configure NodeRestriction plug-in on kubelets. Then, edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the master node and set the --enable-admission-plugins parameter to a value that includes NodeRestriction."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0016

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--enable-admission-plugins")
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.command[i], -1)
	regex.match("NodeRestriction", output[0][1])
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--enable-admission-plugins")
	some i
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, container.args[i], -1)
	regex.match("NodeRestriction", output[0][1])
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the admission control plugin NodeRestriction is set"
	res := result.new(msg, container)
}
