# METADATA
# title: "Ensure that the --use-service-account-credentials argument is set to true"
# description: "Use individual service account credentials for each controller."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0035
#   aliases:
#     - AVD-KCV-0035
#     - KCV0135
#     - ensure-use-service-account-credentials-argument-is-set-to-true
#   long_id: kubernetes-ensure-use-service-account-credentials-argument-is-set-to-true
#   severity: LOW
#   recommended_action: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node to set the below parameter."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0035

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--use-service-account-credentials=true")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--use-service-account-credentials=true")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_controllermanager(container)
	not checkFlag(container)
	msg := "Ensure that the --use-service-account-credentials argument is set to true"
	res := result.new(msg, container)
}
