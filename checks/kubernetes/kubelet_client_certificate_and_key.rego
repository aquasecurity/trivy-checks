# METADATA
# title: "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate"
# description: "Enable certificate based kubelet authentication."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0005
#   aliases:
#     - AVD-KCV-0005
#     - KCV0005
#     - ensure-kubelet-client-certificate-and-kubelet-client-key-are-set
#   long_id: kubernetes-ensure-kubelet-client-certificate-and-kubelet-client-key-are-set
#   severity: LOW
#   recommended_action: "Follow the Kubernetes documentation and set up the TLS connection between the apiserver and kubelets."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0005

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--kubelet-client-certificate")
	kubernetes.command_has_flag(container.command, "--kubelet-client-key")
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--kubelet-client-certificate")
	kubernetes.command_has_flag(container.args, "--kubelet-client-key")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate"
	res := result.new(msg, container)
}
