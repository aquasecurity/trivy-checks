# METADATA
# title: "No wildcard verb roles"
# description: "Check whether role permits wildcard verb on specific resources"
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0045
#   aliases:
#     - AVD-KSV-0045
#     - KSV045
#     - no-wildcard-verb-role
#   long_id: kubernetes-no-wildcard-verb-role
#   severity: CRITICAL
#   recommended_action: "Create a role which does not permit wildcard verb on specific resources"
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KSV045

import rego.v1

resourceRead := ["secrets", "pods", "deployments", "daemonsets", "statefulsets", "replicationcontrollers", "replicasets", "cronjobs", "jobs", "roles", "clusterroles", "rolebindings", "clusterrolebindings", "users", "groups"]

readKinds := ["Role", "ClusterRole"]

resourceAllowAnyVerbOnspecificResource contains input.rules[ru] if {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == resourceRead[_]
	input.rules[ru].verbs[v] == "*"
}

deny contains res if {
	badRule := resourceAllowAnyVerbOnspecificResource[_]
	msg := "Role permits wildcard verb on specific resources"
	res := result.new(msg, badRule)
}
