# METADATA
# title: "Ensure that the --kubelet-https argument is set to true"
# description: "Use https for kubelet connections."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0004
#   aliases:
#     - AVD-KCV-0004
#     - KCV0004
#     - ensure-kubelet-https-argument-is-set-to-true
#   long_id: kubernetes-ensure-kubelet-https-argument-is-set-to-true
#   severity: LOW
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and remove the --kubelet-https parameter."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0004

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--kubelet-https=false")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	check_flag(container)
	msg := "Ensure that the --kubelet-https argument is set to true"
	res := result.new(msg, container)
}
