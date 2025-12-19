# METADATA
# title: "Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive"
# description: "Ensure that the controller manager pod specification file has permissions of 600 or more restrictive."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0050
#   long_id: kubernetes-ensure-controller-manager-pod-specification-file-permissions-set-600-or-more-restrictive
#   aliases:
#     - AVD-KCV-0050
#     - KCV0050
#     - ensure-controller-manager-pod-specification-file-permissions-set
#     - ensure-controller-manager-pod-specification-file-permissions-set-600-or-more-restrictive
#   severity: HIGH
#   recommended_action: "Change the controller manager pod specification file /etc/kubernetes/manifests/kube-controller-manager.yaml permissions of 600 or more restrictive "
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0050

import rego.v1

validate_spec_permission(sp) := {"kubeControllerManagerSpecFilePermission": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.kubeControllerManagerSpecFilePermission.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_spec_permission(input)
	msg := "Ensure that the controller manager pod specification file permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
