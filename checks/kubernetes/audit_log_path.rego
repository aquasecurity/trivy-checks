# METADATA
# title: "Ensure that the --audit-log-path argument is set"
# description: "Enable auditing on the Kubernetes API Server and set the desired audit log path."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0019
#   avd_id: AVD-KCV-0019
#   severity: LOW
#   short_code: ensure-audit-log-path-argument-is-set
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the --audit-log-path parameter."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0019

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--audit-log-path")
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--audit-log-path")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --audit-log-path argument is set"
	res := result.new(msg, container)
}
