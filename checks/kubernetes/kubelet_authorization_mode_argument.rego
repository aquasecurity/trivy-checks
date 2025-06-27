# METADATA
# title: "Ensure that the --authorization-mode argument is not set to AlwaysAllow"
# description: "Do not allow all requests. Enable explicit authorization."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0080
#   aliases:
#     - AVD-KCV-0080
#     - KCV0080
#     - ensure-authorization-mode-argument-set-alwaysallow
#   long_id: kubernetes-ensure-authorization-mode-argument-set-alwaysallow
#   severity: HIGH
#   recommended_action: "edit Kubelet config and set authorization: mode to Webhook."
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0080

import rego.v1

types := ["master", "worker"]

validate_kubelet_authorization_mode(sp) := {"kubeletAuthorizationModeArgumentSet": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {authorization_mode | authorization_mode = sp.info.kubeletAuthorizationModeArgumentSet.values[_]; authorization_mode == "AlwaysAllow"}
	count(violation) > 0
}

validate_kubelet_authorization_mode(sp) := {"kubeletAuthorizationModeArgumentSet": authorization_mode} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletAuthorizationModeArgumentSet.values) == 0
	authorization_mode = {}
}

deny contains res if {
	output := validate_kubelet_authorization_mode(input)
	msg := "Ensure that the --authorization-mode argument is not set to AlwaysAllow"
	res := result.new(msg, output)
}
