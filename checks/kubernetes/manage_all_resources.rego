# METADATA
# title: "Manage all resources"
# description: "Full control of the cluster resources, and therefore also root on all nodes where workloads can run and has access to all pods, secrets, and data."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV046
#   avd_id: AVD-KSV-0046
#   severity: CRITICAL
#   short_code: no-wildcard-resource-clusterrole
#   recommended_actions: "Remove '*' from 'rules.resources'. Provide specific list of resources to be managed by cluster role"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: clusterrole
package builtin.kubernetes.KSV046

import rego.v1

import data.lib.kubernetes

readVerbs := ["create", "update", "delete", "deletecollection", "impersonate", "*", "list", "get"]

readKinds := ["ClusterRole"]

resourceAllowSpecificVerbOnAnyResource contains input.rules[ru] if {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == "*"
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny contains res if {
	badRule := resourceAllowSpecificVerbOnAnyResource[_]
	msg := kubernetes.format(sprintf("%s '%s' shouldn't manage all resources", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, badRule)
}
