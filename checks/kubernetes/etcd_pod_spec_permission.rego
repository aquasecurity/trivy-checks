# METADATA
# title: "Ensure that the etcd pod specification file permissions are set to 600 or more restrictive"
# description: "Ensure that the etcd pod specification file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0054
#   long_id: kubernetes-ensure-etcd-pod-specification-file-permissions-set-600-or-more-restrictive
#   aliases:
#     - AVD-KCV-0054
#     - KCV0054
#     - ensure-etcd-pod-specification-file-permissions-set
#     - ensure-etcd-pod-specification-file-permissions-set-600-or-more-restrictive
#   severity: HIGH
#   recommended_action: "Change the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0054

import rego.v1

validate_spec_permission(sp) := {"kubeEtcdSpecFilePermission": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.kubeEtcdSpecFilePermission.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_spec_permission(input)
	msg := "Ensure that the etcd pod specification file permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
