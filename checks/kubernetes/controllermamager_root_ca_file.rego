# METADATA
# title: "Ensure that the --root-ca-file argument is set as appropriate"
# description: "Allow pods to verify the API server's serving certificate before establishing connections."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0037
#   aliases:
#     - AVD-KCV-0037
#     - KCV0037
#     - ensure-root-ca-file-argument-is-set-as-appropriate
#   long_id: kubernetes-ensure-root-ca-file-argument-is-set-as-appropriate
#   severity: LOW
#   recommended_action: "Edit the Controller Manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml on the Control Plane node and set the --root-ca-file parameter to the certificate bundle file`."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KCV0037

import rego.v1

import data.lib.kubernetes

checkFlag(container) if {
	kubernetes.command_has_flag(container.command, "--root-ca-file")
}

checkFlag(container) if {
	kubernetes.command_has_flag(container.args, "--root-ca-file")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_controllermanager(container)
	not checkFlag(container)
	msg := "Ensure that the --root-ca-file argument is set as appropriate"
	res := result.new(msg, container)
}
