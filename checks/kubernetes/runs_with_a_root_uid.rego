# METADATA
# title: "Containers must not set runAsUser to 0"
# description: "Containers should be forbidden from running with a root UID."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV-0105
#   aliases:
#     - AVD-KSV-0105
#     - KSV105
#     - containers-not-run-as-root
#   long_id: kubernetes-containers-not-run-as-root
#   severity: LOW
#   recommended_action: "Set 'securityContext.runAsUser' to a non-zero integer or leave undefined."
#   input:
#     selector:
#       - type: kubernetes
package builtin.kubernetes.KSV105

import rego.v1

import data.lib.kubernetes

failRootUserId contains securityContext if {
	container := kubernetes.containers[_]
	securityContext := container.securityContext
	securityContext.runAsUser == 0
}

failRootUserId contains securityContext if {
	pod := kubernetes.pods[_]
	securityContext := pod.spec.securityContext
	securityContext.runAsUser == 0
}

deny contains res if {
	cause := failRootUserId[_]
	msg := "securityContext.runAsUser should be set to a value greater than 0"
	res := result.new(msg, cause)
}
