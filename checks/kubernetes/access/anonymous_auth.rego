# METADATA
# title: "Ensure that the --anonymous-auth argument is set to false"
# description: "Disable anonymous requests to the API server."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV0001
#   avd_id: AVD-KCV-0001
#   severity: MEDIUM
#   short_code: ensure-anonymous-auth-argument-is-false
#   recommended_action: "Set '--anonymous-auth' to 'false'."
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KCV0001

import rego.v1

import data.lib.kubernetes

check_flag(container) if {
	some arg in container.args
	contains(arg, "--anonymous-auth=false")
}

check_flag(container) if {
	some cmd in container.command
	contains(cmd, "--anonymous-auth=false")
}

deny contains res if {
	container := kubernetes.containers[_]
	kubernetes.is_apiserver(container)
	not check_flag(container)
	msg := "Ensure that the --anonymous-auth argument is set to false"
	res := result.new(msg, container)
}
