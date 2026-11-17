# METADATA
# title: "Manage EKS IAM Auth ConfigMap"
# description: "Ability to add AWS IAM to RBAC bindings via special EKS configmap."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV-0115
#   long_id: kubernetes-eks-iam-configmap
#   aliases:
#     - AVD-KSV-0115
#     - KSV115
#     - eks-iam-configmap
#     - kubernetes-eks-iam-configmap
#   severity: CRITICAL
#   recommended_actions: "Remove write permission verbs for resource 'configmaps' named 'aws-auth'"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: clusterrole
#         - kind: role
package builtin.kubernetes.KSV115

import rego.v1

import data.lib.kubernetes

readVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

readResource := "configmaps"

resourceName := "aws-auth"

manageEKSIAMAuthConfigmap contains rule if {
	input.kind == readKinds[_]
	some rule in input.rules
	kubernetes.rbac_rule_grants(rule, [readResource], readVerbs)
	resourceName in rule.resourceNames
}

deny contains res if {
	badRule := manageEKSIAMAuthConfigmap[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resource '%s' named '%s' for verbs %s", [kubernetes.kind, kubernetes.name, readResource, resourceName, readVerbs]))
	res := result.new(msg, badRule)
}
