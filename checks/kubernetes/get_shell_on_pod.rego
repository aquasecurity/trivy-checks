# METADATA
# title: "Exec into Pods"
# description: "The ability to exec into a container with privileged access to the host or with an attached SA with higher RBAC permissions is a common escalation path to cluster-admin."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0053
#   aliases:
#     - AVD-KSV-0053
#     - KSV053
#     - no-getting-shell-pods
#   long_id: kubernetes-no-getting-shell-pods
#   severity: HIGH
#   recommended_action: "Remove write permission verbs for resource 'pods/exec'"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: clusterrole
#           - kind: role
package builtin.kubernetes.KSV053

import rego.v1

import data.lib.kubernetes

workloads := ["pods/exec"]

changeVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

execPodsRestricted contains input.rules[ru] if {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == workloads[_]
	input.rules[ru].verbs[v] == changeVerbs[_]
}

deny contains res if {
	badRule := execPodsRestricted[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resource '%s' for verbs %s", [kubernetes.kind, kubernetes.name, workloads, changeVerbs]))
	res := result.new(msg, badRule)
}
