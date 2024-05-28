# METADATA
# title: "Ensure that the admission control plugin AlwaysAdmit is not set"
# description: "Do not allow all requests."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0011
#   avd_id: AVD-KCV-0011
#   severity: LOW
#   short_code: ensure-admission-control-plugin-always-admit-is-not-set
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and either remove the --enable-admission- plugins parameter, or set it to a value that does not include AlwaysAdmit."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0011

import data.lib.kubernetes

check_flag(container) {
	cmd := kubernetes.containers[_].command[_]
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, cmd, -1)
	regex.match("AlwaysAdmit", output[0][1])
}

check_flag(container) {
	arg := kubernetes.containers[_].args[_]
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, arg, -1)
	regex.match("AlwaysAdmit", output[0][1])
}

deny[res] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	check_flag(container)
	msg := "Ensure that the admission control plugin AlwaysAdmit is not set"
	res := result.new(msg, container)
}
