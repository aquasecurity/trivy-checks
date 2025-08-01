# METADATA
# title: "Ensure that the --tls-cert-file argument are set as appropriate"
# description: "Setup TLS connection on the Kubelets."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0088
#   aliases:
#     - AVD-KCV-0088
#     - KCV0088
#     - ensure-tls-cert-file-argument-set-appropriate
#   long_id: kubernetes-ensure-tls-cert-file-argument-set-appropriate
#   severity: CRITICAL
#   recommended_action: "If using a Kubelet config file, edit the file to set tlsCertFile to the location"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0088

import rego.v1

types := ["master", "worker"]

validate_kubelet_tls_cert_file(sp) := {"kubeletTlsCertFileTlsArgumentSet": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {tls_cert_file | tls_cert_file = sp.info.kubeletTlsCertFileTlsArgumentSet.values[_]; not endswith(tls_cert_file, ".crt")}
	count(violation) > 0
}

validate_kubelet_tls_cert_file(sp) := {"kubeletTlsCertFileTlsArgumentSet": tls_cert_file} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletTlsCertFileTlsArgumentSet.values) == 0
	tls_cert_file := {}
}

deny contains res if {
	output := validate_kubelet_tls_cert_file(input)
	msg := "Ensure that the --tls-cert-file argument are set as appropriate"
	res := result.new(msg, output)
}
