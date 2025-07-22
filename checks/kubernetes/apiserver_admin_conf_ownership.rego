# METADATA
# title: "Ensure that the admin config  file ownership is set to root:root"
# description: "Ensure that the admin config  file ownership is set to root:root."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0061
#   aliases:
#     - AVD-KCV-0061
#     - KCV0061
#     - ensure-admin-config-ownership-set-root:root.
#   long_id: kubernetes-ensure-admin-config-ownership-set-root:root.
#   severity: CRITICAL
#   recommended_action: "Change the admin config  file /etc/kubernetes/admin.conf ownership to root:root"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0061

import rego.v1

validate_conf_ownership(sp) := {"adminConfFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.adminConfFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_conf_ownership(input)
	msg := "Ensure that the admin config  file ownership is set to root:root"
	res := result.new(msg, output)
}
