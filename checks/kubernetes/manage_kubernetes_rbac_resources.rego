# METADATA
# title: "Manage Kubernetes RBAC resources"
# description: "An effective level of access equivalent to cluster-admin should not be provided."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0050
#   aliases:
#     - AVD-KSV-0050
#     - KSV050
#     - no-manage-rbac-resources
#   long_id: kubernetes-no-manage-rbac-resources
#   severity: CRITICAL
#   recommended_action: "Remove write permission verbs for resource 'roles' and 'rolebindings'"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: clusterrole
#           - kind: role
package builtin.kubernetes.KSV050

import rego.v1

import data.lib.kubernetes

readVerbs := ["create", "update", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

readResources := ["roles", "rolebindings"]

manageK8sRBACResources contains input.rules[ru] if {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == readResources[_]
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny contains res if {
	badRule := manageK8sRBACResources[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, readResources, readVerbs]))
	res := result.new(msg, badRule)
}
