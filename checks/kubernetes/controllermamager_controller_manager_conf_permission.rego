# METADATA
# title: "Ensure that the controller-manager config file permissions are set to 600 or more restrictive"
# description: "Ensure that the controller-manager config file has permissions of 600 or more restrictive."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0064
#   aliases:
#     - AVD-KCV-0064
#     - KCV0064
#     - ensure-controller-manager-config-file-permissions-set-600-or-more-restrictive
#   long_id: kubernetes-ensure-controller-manager-config-file-permissions-set-600-or-more-restrictive
#   severity: HIGH
#   recommended_action: "Change the controller manager config file /etc/kubernetes/controller-manager.conf permissions of 600 or more restrictive "
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0064

import rego.v1

validate_conf_permission(sp) := {"controllerManagerConfFilePermissions": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.controllerManagerConfFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_conf_permission(input)
	msg := "Ensure that the controller-manager config file permissions is set to 600 or more restrictive"
	res := result.new(msg, output)
}
