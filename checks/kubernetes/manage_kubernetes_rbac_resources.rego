# METADATA
# title: "Do not allow privilege escalation via RBAC resources"
# description: "Check whether role permits escalate, bind, or impersonate on roles/rolebindings, which can lead to privilege escalation."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# - https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-creation-or-update
# custom:
#   id: KSV-0050
#   long_id: kubernetes-no-privilege-escalation-rbac
#   aliases:
#     - AVD-KSV-0050
#     - KSV050
#     - no-manage-rbac-resources
#     - kubernetes-no-manage-rbac-resources
#   severity: CRITICAL
#   recommended_action: "Remove permissions for escalate, bind, and impersonate verbs on roles and rolebindings"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: clusterrole
#         - kind: role
package builtin.kubernetes.KSV050

import rego.v1

import data.lib.kubernetes

criticalVerbs := ["escalate", "bind", "impersonate", "*"]

criticalResources := ["roles", "rolebindings"]

criticalK8sRBACResources contains input.rules[ru] if {
	some ru, r, v
	input.kind == ["Role", "ClusterRole"][_]
	input.rules[ru].resources[r] == criticalResources[_]
	input.rules[ru].verbs[v] == criticalVerbs[_]
}

deny contains res if {
	badRule := criticalK8sRBACResources[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s as they can lead to privilege escalation", [kubernetes.kind, kubernetes.name, criticalResources, criticalVerbs]))
	res := result.new(msg, badRule)
}
