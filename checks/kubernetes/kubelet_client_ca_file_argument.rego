# METADATA
# title: "Ensure that the --client-ca-file argument is set as appropriate"
# description: "Enable Kubelet authentication using certificates."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0081
#   aliases:
#     - AVD-KCV-0081
#     - KCV0081
#     - ensure-client-ca-argument-set-appropriate
#   long_id: kubernetes-ensure-client-ca-argument-set-appropriate
#   severity: CRITICAL
#   recommended_action: "If using a Kubelet config file, edit  the --client-ca-file argument ito appropriate value"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0081

import rego.v1

types := ["master", "worker"]

validate_client_ca_set(sp) := {"kubeletClientCaFileArgumentSet": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {client_ca | client_ca = sp.info.kubeletClientCaFileArgumentSet.values[_]; client_ca == ""}
	count(violation) > 0
}

validate_client_ca_set(sp) := {"kubeletClientCaFileArgumentSet": client_ca} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	count(sp.info.kubeletClientCaFileArgumentSet.values) == 0
	client_ca = {}
}

deny contains res if {
	output := validate_client_ca_set(input)
	msg := "Ensure that the --client-ca-file argument is set as appropriate"
	res := result.new(msg, output)
}
