# METADATA
# title: "User with admin access"
# description: "Either cluster-admin or those granted powerful permissions."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0111
#   aliases:
#     - AVD-KSV-0111
#     - KSV111
#     - cluster-admin0-role-only-used-where-required"
#   long_id: kubernetes-cluster-admin0-role-only-used-where-required"
#   severity: MEDIUM
#   recommended_action: "Remove binding for clusterrole 'cluster-admin', 'admin' or 'edit'"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: rolebinding
#           - kind: clusterrolebinding
package builtin.kubernetes.KSV111

import rego.v1

import data.lib.kubernetes

readRoleRefs := ["cluster-admin", "admin", "edit"]

roleBindings := ["clusterrolebinding", "rolebinding"]

clusterAdminRoleInUse(roleBinding) if {
	lower(kubernetes.kind) == roleBindings[_]
	roleBinding.roleRef.name == readRoleRefs[_]
}

deny contains res if {
	clusterAdminRoleInUse(input)
	msg := kubernetes.format(sprintf("%s '%s' should not bind to roles %s", [kubernetes.kind, kubernetes.name, readRoleRefs]))
	res := result.new(msg, input.metadata)
}
