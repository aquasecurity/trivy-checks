# METADATA
# title: "Ensure that the controller-manager config  file ownership is set to root:root"
# description: "Ensure that the controller-manager config  file ownership is set to root:root."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0065
#   aliases:
#     - AVD-KCV-0065
#     - KCV0065
#     - ensure-controller-manager-config-ownership-set-root:root.
#   long_id: kubernetes-ensure-controller-manager-config-ownership-set-root:root.
#   severity: HIGH
#   recommended_action: "Change the controller-manager config  file /etc/kubernetes/controller-manager.conf ownership to root:root"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0065

import rego.v1

validate_conf_ownership(sp) := {"controllerManagerConfFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.controllerManagerConfFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_conf_ownership(input)
	msg := "Ensure that the controller-manager config file ownership is set to root:root"
	res := result.new(msg, output)
}
