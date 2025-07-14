# METADATA
# title: "Container capabilities must only include NET_BIND_SERVICE"
# description: "Containers must drop ALL capabilities, and are only permitted to add back the NET_BIND_SERVICE capability."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV-0106
#   aliases:
#     - AVD-KSV-0106
#     - KSV106
#     - drop-caps-add-bind-svc
#   long_id: kubernetes-drop-caps-add-bind-svc
#   severity: LOW
#   recommended_action: "Set 'spec.containers[*].securityContext.capabilities.drop' to 'ALL' and only add 'NET_BIND_SERVICE' to 'spec.containers[*].securityContext.capabilities.add'."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KSV106

import rego.v1

import data.lib.kubernetes

hasDropAll(container) if {
	upper(container.securityContext.capabilities.drop[_]) == "ALL"
}

containersWithoutDropAll contains container if {
	container := kubernetes.containers[_]
	not hasDropAll(container)
}

containersWithDropAll contains container if {
	container := kubernetes.containers[_]
	hasDropAll(container)
}

deny contains res if {
	container := containersWithoutDropAll[_]
	msg := "container should drop all"
	res := result.new(msg, container)
}

deny contains res if {
	container := containersWithDropAll[_]
	add := container.securityContext.capabilities.add[_]
	add != "NET_BIND_SERVICE"
	msg := "container should not add stuff"
	res := result.new(msg, container.securityContext.capabilities)
}
