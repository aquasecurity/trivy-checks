# METADATA
# title: "Manage Kubernetes networking"
# description: "The ability to control which pods get service traffic directed to them allows for interception attacks. Controlling network policy allows for bypassing lateral movement restrictions."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0056
#   aliases:
#     - AVD-KSV-0056
#     - KSV056
#     - no-manage-networking-resources
#   long_id: kubernetes-no-manage-networking-resources
#   severity: HIGH
#   recommended_action: "Networking resources are only allowed for verbs 'list', 'watch', 'get'"
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: clusterrole
#           - kind: role
package builtin.kubernetes.KSV056

import rego.v1

import data.lib.kubernetes

readKinds := ["Role", "ClusterRole"]

readVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readResources := ["services", "endpoints", "endpointslices", "networkpolicies", "ingresses"]

managekubernetesNetworking contains input.rules[ru] if {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == readResources[_]
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny contains res if {
	badRule := managekubernetesNetworking[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, readResources, readVerbs]))
	res := result.new(msg, badRule)
}
