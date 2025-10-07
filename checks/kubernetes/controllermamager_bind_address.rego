# METADATA
# title: "Ensure that the --bind-address argument is set to 127.0.0.1"
# description: "Do not bind the scheduler service to non-loopback insecure addresses."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0039
#   avd_id: AVD-KCV-0039
#   severity: LOW
#   short_code: ensure-controller-manager-bind-address-is-loopback
#   recommended_action: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and ensure the correct value for the --bind-address parameter"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0039

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
	kubernetes.is_controllermanager(container)
	not checkFlag(container)
	msg := "Ensure that the --bind-address argument is set to 127.0.0.1"
	res := result.new(msg, container)
}
