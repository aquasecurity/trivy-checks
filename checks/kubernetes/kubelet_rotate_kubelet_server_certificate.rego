# METADATA
# title: "Verify that the RotateKubeletServerCertificate argument is set to true"
# description: "Enable kubelet server certificate rotation."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0091
#   aliases:
#     - AVD-KCV-0091
#     - KCV0091
#     - ensure-rotate-kubelet-server-certificate-argument-set-true
#   long_id: kubernetes-ensure-rotate-kubelet-server-certificate-argument-set-true
#   severity: HIGH
#   recommended_action: "Edit the kubelet service file /etc/kubernetes/kubelet.conf and set --feature-gates=RotateKubeletServerCertificate=true"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0091

import rego.v1

types := ["master", "worker"]

validate_kubelet_rotate_kubelet_server_certificate(sp) := {"kubeletRotateKubeletServerCertificateArgumentSet": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {rotate_kubelet_server_certificate | rotate_kubelet_server_certificate = sp.info.kubeletRotateKubeletServerCertificateArgumentSet.values[_]; rotate_kubelet_server_certificate == "false"}
	count(violation) > 0
}

validate_kubelet_rotate_kubelet_server_certificate(sp) := {"kubeletRotateKubeletServerCertificateArgumentSet": rotate_kubelet_server_certificate} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletRotateKubeletServerCertificateArgumentSet.values) == 0
	rotate_kubelet_server_certificate = {}
}

deny contains res if {
	output := validate_kubelet_rotate_kubelet_server_certificate(input)
	msg := "Verify that the RotateKubeletServerCertificate argument is set to true"
	res := result.new(msg, output)
}
