# METADATA
# title: "Ensure that the etcd data directory permissions are set to 700 or more restrictive"
# description: "Ensure that the etcd data directory has permissions of 700 or more restrictive."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://www.cisecurity.org/benchmark/kubernetes
# custom:
#   id: KCV-0058
#   aliases:
#     - AVD-KCV-0058
#     - KCV0058
#     - ensure-etcd-data-directory-permissions-set-700-or-more-restrictive
#   long_id: kubernetes-ensure-etcd-data-directory-permissions-set-700-or-more-restrictive
#   severity: LOW
#   recommended_action: "Change the etcd data directory /var/lib/etcd permissions of 700 or more restrictive "
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: nodeinfo
package builtin.kubernetes.KCV0058

import rego.v1

validate_spec_permission(sp) := {"etcdDataDirectoryPermissions": permission} if {
	sp.kind == "NodeInfo"
	sp.type == "master"
	permission := sp.info.etcdDataDirectoryPermissions.values[_]
	permission > 700
}

deny contains res if {
	output := validate_spec_permission(input)
	msg := "Ensure that the etcd data directory permissions are set to 700 or more restrictive"
	res := result.new(msg, output)
}
