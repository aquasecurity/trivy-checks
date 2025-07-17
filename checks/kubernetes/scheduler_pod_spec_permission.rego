# METADATA
# title: "Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive"
# description: "Ensure that the scheduler pod specification file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0052
#   aliases:
#     - AVD-KCV-0052
#     - KCV0052
#     - ensure-scheduler-pod-specification-file-permissions-set
#   severity: HIGH
#   short_code: ensure-scheduler-pod-specification-file-permissions-set-600-or-more-restrictive
#   recommended_action: "Change the scheduler pod specification file /etc/kubernetes/manifests/kube-scheduler.yaml permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0052

import rego.v1

validate_spec_permission(sp) := {"kubeSchedulerSpecFilePermission": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.kubeSchedulerSpecFilePermission.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_spec_permission(input)
	msg := "Ensure that the scheduler pod specification file permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
