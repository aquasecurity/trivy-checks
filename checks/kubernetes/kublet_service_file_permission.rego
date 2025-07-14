# METADATA
# title: "Ensure that the kubelet service file permissions are set to 600 or more restrictive"
# description: "Ensure that the kubelet service file has permissions of 600 or more restrictive."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0069
#   aliases:
#     - AVD-KCV-0069
#     - KCV0069
#     - ensure-kubelet-service-file-permissions-set-600-or-more-restrictive
#   long_id: kubernetes-ensure-kubelet-service-file-permissions-set-600-or-more-restrictive
#   severity: HIGH
#   recommended_action: "Change the kubelet service file /etc/systemd/system/kubelet.service.d/10-kubeadm.conf permissions of 600 or more restrictive "
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0069

import rego.v1

types := ["master", "worker"]

validate_service_file_permission(sp) := {"kubeletServiceFilePermissions": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {permission | permission = sp.info.kubeletServiceFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_service_file_permission(input)
	msg := "Ensure that the kubelet service file permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
