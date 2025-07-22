# METADATA
# title: "Ensure that the client certificate authorities file ownership is set to root:root"
# description: "Ensure that the certificate authorities file ownership is set to root:root."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0076
#   aliases:
#     - AVD-KCV-0076
#     - KCV0076
#     - ensure-certificate_authorities-ownership-set-root:root
#   long_id: kubernetes-ensure-certificate-authorities-ownership-set-root:root
#   severity: CRITICAL
#   recommended_action: "Change the certificate authorities file ownership to root:root"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0076

import rego.v1

types := ["master", "worker"]

validate_certificate_authorities_ownership(sp) := {"certificateAuthoritiesFileOwnership": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {ownership | ownership = sp.info.certificateAuthoritiesFileOwnership.values[_]; not ownership == "root:root"}
	count(violation) > 0
}

deny contains res if {
	output := validate_certificate_authorities_ownership(input)
	msg := "Ensure that the certificate authorities file ownership is set to root:root."
	res := result.new(msg, output)
}
