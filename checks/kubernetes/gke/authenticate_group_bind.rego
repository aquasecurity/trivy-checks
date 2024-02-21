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
#   avd_id: AVD-KSV-01011
#   severity: CRITICAL
#   short_code: no-system-authenticated-group-bind
#   recommended_action: "Remove system:authenticated group binding from clusterrolebinding or rolebinding."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: rolebinding
#         - kind: clusterrolebinding

package appshield.kubernetes.KSV01011

import data.k8s
import data.lib.kubernetes

readRoleRefs := ["system:authenticated"]

readKinds := ["RoleBinding", "ClusterRolebinding"]

authenticatedGroupBind(roleBinding) {
	kubernetes.kind == readKinds[_]
	kubernetes.object.subjects[_].name == readRoleRefs[_]
}

deny[res] {
	contains(k8s.version, "-gke")
	authenticatedGroupBind(input)
	msg := kubernetes.format(sprintf("%s '%s' should not bind to roles %s", [kubernetes.kind, kubernetes.name, readRoleRefs]))
	res := result.new(msg, input.metadata)
}
