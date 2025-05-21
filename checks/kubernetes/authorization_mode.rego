# METADATA
# title: "Ensure that the --authorization-mode argument is not set to AlwaysAllow"
# description: "Do not always authorize all requests."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0007
#   avd_id: AVD-KCV-0007
#   severity: LOW
#   short_code: ensure-authorization-mode-argument-is-not-set-to-alwaysallow
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --authorization-mode parameter to values other than AlwaysAllow. "
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0007

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	some i
	output := regex.find_all_string_submatch_n(`--authorization-mode=([^\s]+)`, container.command[i], -1)
	regex.match("AlwaysAllow", output[0][1])
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	check_flag(container)
	msg := "Ensure that the --authorization-mode argument is not set to AlwaysAllow"
	res := result.new(msg, container)
}
