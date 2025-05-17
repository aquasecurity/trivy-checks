# METADATA
# title: "Ensure that the --service-account-lookup argument is set to true"
# description: "Validate service account before validating token."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0024
#   avd_id: AVD-KCV-0024
#   severity: LOW
#   short_code: ensure-service-account-lookup-argument-is-set-to-true
#   recommended_action: "Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml on the Control Plane node and set the below parameter."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0024

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	kubernetes.command_has_flag(container.command, "--service-account-lookup=false")
}

check_flag(container) if {
	kubernetes.command_has_flag(container.args, "--service-account-lookup=false")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	check_flag(container)
	msg := "Ensure that the --service-account-lookup argument is set to true"
	res := result.new(msg, container)
}
