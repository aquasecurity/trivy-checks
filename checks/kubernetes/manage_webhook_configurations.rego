# METADATA
# title: "Manage webhookconfigurations"
# description: "Webhooks can silently intercept or actively mutate/block resources as they are being created or updated. This includes secrets and pod specs."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV114
#   avd_id: AVD-KSV-0114
#   severity: CRITICAL
#   short_code: no-manage-webhook
#   recommended_actions: "Remove webhook configuration resources/verbs, acceptable values for verbs ['get', 'list', 'watch']"
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: clusterrole
#         - kind: role
package builtin.kubernetes.KSV114

import rego.v1

import data.lib.kubernetes

readVerbs := ["create", "update", "patch", "delete", "deletecollection", "impersonate", "*"]

readKinds := ["Role", "ClusterRole"]

readResource := ["mutatingwebhookconfigurations", "validatingwebhookconfigurations"]

manageWebhookConfig contains input.rules[ru] if {
	some ru, r, v
	input.kind == readKinds[_]
	input.rules[ru].resources[r] == readResource[_]
	input.rules[ru].verbs[v] == readVerbs[_]
}

deny contains res if {
	badRule := manageWebhookConfig[_]
	msg := kubernetes.format(sprintf("%s '%s' should not have access to resources %s for verbs %s", [kubernetes.kind, kubernetes.name, readResource, readVerbs]))
	res := result.new(msg, badRule)
}
