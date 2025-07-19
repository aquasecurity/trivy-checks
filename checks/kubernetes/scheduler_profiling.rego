# METADATA
# title: "Ensure that the --profiling argument is set to false"
# description: "Disable profiling, if not needed."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0040
#   aliases:
#     - AVD-KCV-0040
#     - KCV0040
#     - ensure-scheduler-profiling-argument-set-to-false
#   severity: LOW
#   short_code: ensure-profiling-argument-is-set-to-false
#   recommended_action: "Edit the Scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml file on the Control Plane node and set the below parameter."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0040

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--profiling=false")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--profiling=false")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_scheduler(container)
	not checkFlag(container)
	msg := "Ensure that the --profiling argument is set to false"
	res := result.new(msg, container)
}
