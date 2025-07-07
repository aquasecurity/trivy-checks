# METADATA
# title: "Ensure that the Kubernetes PKI certificate file permission is set to 600"
# description: "Ensure that the Kubernetes PKI certificate file permission is set to 600."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0068
#   aliases:
#     - AVD-KCV-0068
#     - KCV0068
#     - ensure-kubernetes-pki-cert-file-permission-set-600.
#   long_id: kubernetes-ensure-kubernetes-pki-cert-file-permission-set-600.
#   severity: HIGH
#   recommended_action: "Change the Kubernetes PKI certificate file /etc/kubernetes/pki/*.crt permission to 600"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0068

import rego.v1

validate_pki_cert_permission(sp) := {"kubernetesPKICertificateFilePermissions": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {permission | permission = sp.info.kubernetesPKICertificateFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_pki_cert_permission(input)
	msg := "Ensure that the Kubernetes PKI certificate file permission is set to 600"
	res := result.new(msg, output)
}
