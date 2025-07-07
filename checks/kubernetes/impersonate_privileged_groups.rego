# METADATA
# title: "Do not allow impersonation of privileged groups"
# description: "Check whether role permits impersonating privileged groups"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/rbac-good-practices/
# custom:
#   id: KSV043
#   avd_id: AVD-KSV-0043
#   severity: CRITICAL
#   short_code: no-impersonate-privileged-groups
#   recommended_action: "Create a role which does not permit to impersonate privileged groups if not needed"
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV043

import rego.v1

readKinds := ["Role", "ClusterRole"]

impersonatePrivilegedGroups contains input.rules[ru] if {
	some ru
	input.kind == readKinds[_]
	input.rules[ru].apiGroups[_] == "*"
	input.rules[ru].resources[_] == "groups"
	input.rules[ru].verbs[_] == "impersonate"
}

deny contains res if {
	badRule := impersonatePrivilegedGroups[_]
	msg := "Role permits impersonation of privileged groups"
	res := result.new(msg, badRule)
}
