# METADATA
# title: "Ensure that the admission control plugin AlwaysAdmit is not set"
# description: "Do not allow all requests."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0011
#   aliases:
#     - AVD-KCV-0011
#     - KCV0011
#     - ensure-admission-control-plugin-always-admit-is-not-set
#   long_id: kubernetes-ensure-admission-control-plugin-always-admit-is-not-set
#   severity: LOW
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and either remove the --enable-admission- plugins parameter, or set it to a value that does not include AlwaysAdmit."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0011

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	some cmd in container.command
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, cmd, -1)
	regex.match("AlwaysAdmit", output[0][1])
}

check_flag(container) if {
	some arg in container.args
	output := regex.find_all_string_submatch_n(`--enable-admission-plugins=([^\s]+)`, arg, -1)
	regex.match("AlwaysAdmit", output[0][1])
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	check_flag(container)
	msg := "Ensure that the admission control plugin AlwaysAdmit is not set"
	res := result.new(msg, container)
}
