# METADATA
# title: "Ensure that the certificate authorities file permissions are set to 600 or more restrictive"
# description: "Ensure that the certificate authorities file has permissions of 600 or more restrictive."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0075
#   aliases:
#     - AVD-KCV-0075
#     - KCV0075
#     - ensure-certificate-authorities-file-permissions-600-or-more-restrictive.
#   long_id: kubernetes-ensure-certificate-authorities-file-permissions-600-or-more-restrictive.
#   severity: CRITICAL
#   recommended_action: "Change the certificate authorities file permissions to 600 or more restrictive if exist"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0075

import rego.v1

types := ["master", "worker"]

validate_certificate_authorities_file_permission(sp) := {"certificateAuthoritiesFilePermissions": violation} if {
	sp.kind == "NodeInfo"
	sp.type == types[_]
	violation := {permission | permission = sp.info.certificateAuthoritiesFilePermissions.values[_]; permission > 600}
	count(violation) > 0
}

deny contains res if {
	output := validate_certificate_authorities_file_permission(input)
	msg := "Ensure that the certificate authorities file permissions are set to 600 or more restrictive"
	res := result.new(msg, output)
}
