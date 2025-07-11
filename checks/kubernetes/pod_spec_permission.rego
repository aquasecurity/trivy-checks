# METADATA
# title: "Ensure that the API server pod specification file permissions are set to 600 or more restrictive"
# description: "Ensure that the API server pod specification file has permissions of 600 or more restrictive."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0048
#   aliases:
#     - AVD-KCV-0048
#     - KCV0048
#     - ensure-api-server-pod-specification-file-permissions-set-600-or-more-restrictive
#   long_id: kubernetes-ensure-api-server-pod-specification-file-permissions-set-600-or-more-restrictive
#   severity: HIGH
#   recommended_action: "Change the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml permissions of 600 or more restrictive "
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0048

import rego.v1

validate_spec_permission(sp) := {"kubeAPIServerSpecFilePermission": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.kubeAPIServerSpecFilePermission.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_spec_permission(input)
	msg := "Ensure that the API server pod specification file permissions is set to 600 or more restrictive"
	res := result.new(msg, output)
}
