# METADATA
# title: "Ensure that the --kubelet-certificate-authority argument is set as appropriate"
# description: "Verify kubelet's certificate before establishing connection."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0006
#   avd_id: AVD-KCV-0006
#   severity: LOW
#   short_code: ensure-kubelet-certificate-authority-argument-is-set
#   recommended_action: "Follow the Kubernetes documentation and setup the TLS connection between the apiserver and kubelets. "
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0006

import data.lib.kubernetes

check_flag(container) {
	kubernetes.command_has_flag(container.command, "--kubelet-certificate-authority")
}

check_flag(container) {
	kubernetes.command_has_flag(container.args, "--kubelet-certificate-authority")
}

deny[res] {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --kubelet-certificate-authority argument is set as appropriate"
	res := result.new(msg, container)
}
