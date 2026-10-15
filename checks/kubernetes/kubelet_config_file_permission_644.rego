# METADATA
# title: "Ensure that the --kubeconfig kubelet.conf file permissions are set to 644 or more restrictive"
# description: "Ensure that the kubelet.conf file has permissions of 644 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0094
#   long_id: kubernetes-ensure-kubelet.conf-file-permissions-644-or-more-restrictive.
#   aliases:
#     - AVD-KCV-0094
#     - KCV0094
#     - ensure-kubelet.conf-file-permissions-644-or-more-restrictive.
#     - kubernetes-ensure-kubelet.conf-file-permissions-644-or-more-restrictive.
#   severity: HIGH
#   recommended_action: "Change the kubelet.conf file permissions to 644 or more restrictive if exist"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0094

import rego.v1

types := ["master", "worker"]

validate_kubelet_file_permission(sp) := {"kubeletConfFilePermissions": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {permission | permission = sp.info.kubeletConfFilePermissions.values[_]; permission > 644}
	count(violation) > 0
}

deny contains res if {
	output := validate_kubelet_file_permission(input)
	msg := "Ensure that the --kubeconfig kubelet.conf file permissions are set to 644 or more restrictive"
	res := result.new(msg, output)
}
