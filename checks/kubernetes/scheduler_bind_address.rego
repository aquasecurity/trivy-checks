# METADATA
# title: "Ensure that the --bind-address argument is set to 127.0.0.1"
# description: "Do not bind the scheduler service to non-loopback insecure addresses."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0041
#   aliases:
#     - AVD-KCV-0041
#     - KCV0041
#     - ensure-scheduler-bind-address-is-loopback
#   severity: LOW
#   short_code: ensure-scheduler-bind-address-is-loopback
#   recommended_action: "Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml on the Control Plane node and ensure the correct value for the --bind-address parameter."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0041

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--bind-address=127.0.0.1")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--bind-address=127.0.0.1")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_scheduler(container)
	not checkFlag(container)
	msg := "Ensure that the --bind-address argument is set to 127.0.0.1"
	res := result.new(msg, container)
}
