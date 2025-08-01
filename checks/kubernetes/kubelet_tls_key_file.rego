# METADATA
# title: "Ensure that the --tls-key-file argument are set as appropriate"
# description: "Setup TLS connection on the Kubelets."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0089
#   aliases:
#     - AVD-KCV-0089
#     - KCV0089
#     - ensure-tls-key-file-argument-set-appropriate
#   long_id: kubernetes-ensure-tls-key-file-argument-set-appropriate
#   severity: CRITICAL
#   recommended_action: "If using a Kubelet config file, edit the file to set tlskeyFile to the location"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0089

import rego.v1

types := ["master", "worker"]

validate_kubelet_tls_key_file(sp) := {"kubeletTlsPrivateKeyFileArgumentSet": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {tls_key_file | tls_key_file = sp.info.kubeletTlsPrivateKeyFileArgumentSet.values[_]; not endswith(tls_key_file, ".key")}
	count(violation) > 0
}

validate_kubelet_tls_key_file(sp) := {"kubeletTlsPrivateKeyFileArgumentSet": tls_key_file} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletTlsPrivateKeyFileArgumentSet.values) == 0
	tls_key_file := {}
}

deny contains res if {
	output := validate_kubelet_tls_key_file(input)
	msg := "Ensure that the --tls-key-file argument are set as appropriate"
	res := result.new(msg, output)
}
