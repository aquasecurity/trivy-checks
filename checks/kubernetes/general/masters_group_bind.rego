# METADATA
# title: "system:authenticate group access binding"
# description: "Binding to system:authenticate group to any clusterrole or role is a security risk."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://orca.security/resources/blog/sys-all-google-kubernetes-engine-risk/
# custom:
#   id: KSV01011
#   avd_id: AVD-KSV-0123
#   severity: CRITICAL
#   short_code: no-system-authenticated-group-bind
#   recommended_action: "Remove system:authenticated group binding from clusterrolebinding or rolebinding."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: rolebinding
#         - kind: clusterrolebinding

package appshield.kubernetes.KSV0123

import data.k8s
import data.lib.kubernetes

readRoleRefs := ["system:masters"]

readKinds := ["RoleBinding", "ClusterRolebinding"]

mastersGroupBind(roleBinding) {
	kubernetes.kind == readKinds[_]
	kubernetes.object.subjects[_].name == readRoleRefs[_]
}

deny[res] {
	mastersGroupBind(input)
	msg := kubernetes.format(sprintf("%s '%s' should not bind to roles %s", [kubernetes.kind, kubernetes.name, readRoleRefs]))
	res := result.new(msg, input.metadata)
}
