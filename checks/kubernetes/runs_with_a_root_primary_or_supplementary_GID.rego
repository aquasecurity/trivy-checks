# METADATA
# title: "Runs with a root primary or supplementary GID"
# description: "According to pod security standard 'Non-root groups', containers should be forbidden from running with a root primary or supplementary GID."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubesec.io/basics/containers-securitycontext-runasuser/
# custom:
#   id: KSV-0116
#   aliases:
#     - AVD-KSV-0116
#     - KSV116
#     - primary-supplementary-gid
#   long_id: kubernetes-primary-supplementary-gid
#   severity: LOW
#   recommended_actions: "Set 'containers[].securityContext.runAsGroup' to a non-zero integer or leave undefined."
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
package builtin.kubernetes.KSV116

import rego.v1

import data.lib.kubernetes

default failRootGroupId := false

# getContainersWithRootGroupId returns a list of containers
# with root group id set
getContainersWithRootGroupId contains name if {
	container := kubernetes.containers[_]
	container.securityContext.runAsGroup == 0
	name := container.name
}

# failRootGroupId is true if root group id is set on pod
failRootGroupId if {
	pod := kubernetes.pods[_]
	pod.spec.securityContext.runAsGroup == 0
}

# failRootGroupId is true if root group id is set on pod
failRootGroupId if {
	pod := kubernetes.pods[_]
	gid := pod.spec.securityContext.supplementalGroups[_]
	gid == 0
}

# failRootGroupId is true if root group id is set on pod
failRootGroupId if {
	pod := kubernetes.pods[_]
	pod.spec.securityContext.fsGroup == 0
}

deny contains res if {
	failRootGroupId
	output := failRootGroupId
	msg := kubernetes.format(sprintf("%s %s in %s namespace should set spec.securityContext.runAsGroup, spec.securityContext.supplementalGroups[*] and spec.securityContext.fsGroup to integer greater than 0", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, output)
}
