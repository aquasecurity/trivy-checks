# METADATA
# title: "Anonymous user access binding"
# description: "Binding to anonymous user to any clusterrole or role is a security risk."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://blog.aquasec.com/kubernetes-exposed-one-yaml-away-from-disaster
# custom:
#   id: KSV-0122
#   aliases:
#     - AVD-KSV-0122
#     - KSV122
#     - no-anonymous-user-bind
#   long_id: kubernetes-no-anonymous-user-bind
#   severity: CRITICAL
#   recommended_action: "Remove anonymous user binding from clusterrolebinding or rolebinding."
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: rolebinding
#           - kind: clusterrolebinding

package appshield.kubernetes.KSV122

import rego.v1

import data.lib.kubernetes

readRoleRefs := {"system:unauthenticated", "system:anonymous"}

anonymousUserBind if {
	kubernetes.is_role_binding_kind
	kubernetes.object.subjects[_].name in readRoleRefs
}

deny contains res if {
	anonymousUserBind
	msg := kubernetes.format(sprintf("%s '%s' should not bind to roles %s", [kubernetes.kind, kubernetes.name, readRoleRefs]))
	res := result.new(msg, input.metadata)
}
