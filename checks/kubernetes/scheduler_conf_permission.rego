# METADATA
# title: "Ensure that the scheduler config file permissions are set to 600 or more restrictive"
# description: "Ensure that the scheduler config file has permissions of 600 or more restrictive."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0062
#   aliases:
#     - AVD-KCV-0062
#     - KCV0062
#     - ensure-scheduler-config-file-permissions-set-600-or-more-restrictive
#   long_id: kubernetes-ensure-scheduler-config-file-permissions-set-600-or-more-restrictive
#   severity: HIGH
#   recommended_action: "Change the scheduler config file /etc/kubernetes/scheduler.conf permissions of 600 or more restrictive "
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0062

import rego.v1

validate_conf_permission(sp) := {"schedulerConfFilePermissions": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.schedulerConfFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_conf_permission(input)
	msg := "Ensure that the scheduler config file permissions is set to 600 or more restrictive"
	res := result.new(msg, output)
}
