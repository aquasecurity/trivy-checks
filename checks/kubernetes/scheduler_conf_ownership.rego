# METADATA
# title: "Ensure that the scheduler config  file ownership is set to root:root"
# description: "Ensure that the scheduler config  file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   avd_id: AVD-KCV-0063
#   severity: HIGH
#   short_code: ensure-scheduler-config-ownership-set-root:root.
#   recommended_action: "Change the scheduler config  file /etc/kubernetes/scheduler.conf ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0063

import rego.v1

validate_conf_ownership(sp) := {"schedulerConfFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	ownership := sp.info.schedulerConfFileOwnership.values[_]
	violation := {ownership | ownership = sp.info.schedulerConfFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_conf_ownership(input)
	msg := "Ensure that the scheduler config  file ownership is set to root:root"
	res := result.new(msg, output)
}
