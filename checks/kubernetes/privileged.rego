# METADATA
# title: "Privileged"
# description: "Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV-0017
#   aliases:
#     - AVD-KSV-0017
#     - KSV017
#     - no-privileged-containers
#   long_id: kubernetes-no-privileged-containers
#   severity: HIGH
#   recommended_action: "Change 'containers[].securityContext.privileged' to 'false'."
#   input:
#     selector:
#       - type: kubernetes
#         subtypes:
#           - kind: pod
#           - kind: replicaset
#           - kind: replicationcontroller
#           - kind: deployment
#           - kind: deploymentconfig
#           - kind: statefulset
#           - kind: daemonset
#           - kind: cronjob
#           - kind: job
#   examples: checks/kubernetes/privileged.yaml
package builtin.kubernetes.KSV017

import rego.v1

import data.lib.kubernetes

default failPrivileged := false

# getPrivilegedContainers returns all containers which have
# securityContext.privileged set to true.
getPrivilegedContainers contains container if {
	container := kubernetes.containers[_]
	container.securityContext.privileged == true
}

deny contains res if {
	output := getPrivilegedContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.privileged' to false", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
