# METADATA
# title: "system:masters group access binding"
# description: "Binding to system:masters group to any clusterrole or role is a security risk."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://www.aquasec.com/blog/kubernetes-authorization/
# custom:
#   id: KSV0123
#   avd_id: AVD-KSV-0123
#   severity: CRITICAL
#   short_code: no-system-masters-group-bind
#   recommended_action: "Remove system:masters group binding from clusterrolebinding or rolebinding."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: rolebinding
#         - kind: clusterrolebinding

package appshield.kubernetes.KSV0123

import rego.v1

import data.lib.kubernetes

readRoleRefs := {"system:masters"}

mastersGroupBind if {
	kubernetes.is_role_binding_kind
	kubernetes.object.subjects[_].name in readRoleRefs
}

deny contains res if {
	mastersGroupBind
	msg := kubernetes.format(sprintf("%s '%s' should not bind to roles %s", [kubernetes.kind, kubernetes.name, readRoleRefs]))
	res := result.new(msg, input.metadata)
}
