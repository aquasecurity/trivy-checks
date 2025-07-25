# METADATA
# title: "Ensure that the --service-account-private-key-file argument is set as appropriate"
# description: "Explicitly set a service account private key file for service accounts on the controller manager."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0036
#   aliases:
#     - AVD-KCV-0036
#     - KCV0036
#     - ensure-service-account-private-key-file-argument-is-set-as-appropriate
#   long_id: kubernetes-ensure-service-account-private-key-file-argument-is-set-as-appropriate
#   severity: LOW
#   recommended_action: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --service-account-private-key-file parameter to the private key file for service accounts."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0036

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--service-account-private-key-file")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--service-account-private-key-file")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_controllermanager(container)
	not checkFlag(container)
	msg := "Ensure that the --service-account-private-key-file argument is set as appropriate"
	res := result.new(msg, container)
}
