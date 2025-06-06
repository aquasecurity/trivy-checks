# METADATA
# title: "Ensure that the Kubernetes PKI directory and file file ownership is set to root:root"
# description: "Ensure that the Kubernetes PKI directory and file file ownership is set to root:root."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   avd_id: AVD-KCV-0066
#   severity: CRITICAL
#   short_code: ensure-kubernetes-pki-directory-file-ownership-set-root:root.
#   recommended_action: "Change the Kubernetes PKI directory and file file /etc/kubernetes/pki/ ownership to root:root"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: nodeinfo
package builtin.kubernetes.KCV0066

import rego.v1

validate_pki_directory_ownership(sp) := {"kubePKIDirectoryFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	violation := {ownership | ownership = sp.info.kubePKIDirectoryFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_pki_directory_ownership(input)
	msg := "Ensure that the Kubernetes PKI directory and file file ownership is set to root:root"
	res := result.new(msg, output)
}
