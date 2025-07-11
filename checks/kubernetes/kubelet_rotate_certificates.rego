# METADATA
# title: "Ensure that the --rotate-certificates argument is not set to false"
# description: "Enable kubelet client certificate rotation."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0090
#   aliases:
#     - AVD-KCV-0090
#     - KCV0090
#     - ensure-rotate-certificates-argument-set-false
#   long_id: kubernetes-ensure-rotate-certificates-argument-set-false
#   severity: HIGH
#   recommended_action: "If using a Kubelet config file, edit the file to add the line rotateCertificates: true or remove it altogether to use the default value."
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0090

import rego.v1

types := ["master", "worker"]

validate_kubelet_rotate_certificates(sp) := {"kubeletRotateCertificatesArgumentSet": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {rotate_certificates | rotate_certificates = sp.info.kubeletRotateCertificatesArgumentSet.values[_]; rotate_certificates == "false"}
	count(violation) > 0
}

validate_kubelet_rotate_certificates(sp) := {"kubeletRotateCertificatesArgumentSet": rotate_certificates} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletRotateCertificatesArgumentSet.values) == 0
	rotate_certificates = {}
}

deny contains res if {
	output := validate_kubelet_rotate_certificates(input)
	msg := "Ensure that the --rotate-certificates argument is not set to false"
	res := result.new(msg, output)
}
