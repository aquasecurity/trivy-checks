# METADATA
# title: "Can elevate its own privileges"
# description: "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV001
#   avd_id: AVD-KSV-0001
#   severity: MEDIUM
#   short_code: no-self-privesc
#   recommended_action: "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
#         - kind: replicaset
#         - kind: replicationcontroller
#         - kind: deployment
#         - kind: deploymentconfig
#         - kind: statefulset
#         - kind: daemonset
#         - kind: cronjob
#         - kind: job
#   examples: checks/kubernetes/can_elevate_its_own_privileges.yaml
package builtin.kubernetes.KSV001

import rego.v1

import data.lib.kubernetes

default checkAllowPrivilegeEscalation := false

# getNoPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to false.
getNoPrivilegeEscalationContainers contains container if {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.allowPrivilegeEscalation == false
	container := allContainers.name
}

# getPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to true or not set.
getPrivilegeEscalationContainers contains container if {
	container := kubernetes.containers[_]
	not getNoPrivilegeEscalationContainers[container.name]
}

deny contains res if {
	output := getPrivilegeEscalationContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.allowPrivilegeEscalation' to false", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
