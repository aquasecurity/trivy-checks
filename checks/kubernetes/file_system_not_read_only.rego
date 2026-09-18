# METADATA
# title: "Root file system is not read-only"
# description: "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubesec.io/basics/containers-securitycontext-readonlyrootfilesystem-true/
# custom:
#   id: KSV-0014
#   long_id: kubernetes-use-readonly-filesystem
#   aliases:
#     - AVD-KSV-0014
#     - KSV014
#     - use-readonly-filesystem
#     - kubernetes-use-readonly-filesystem
#   severity: HIGH
#   recommended_action: "Change 'containers[].securityContext.readOnlyRootFilesystem', 'initContainers[].securityContext.readOnlyRootFilesystem' and 'ephemeralContainers[].securityContext.readOnlyRootFilesystem' to 'true'."
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
package builtin.kubernetes.KSV014

import rego.v1

import data.lib.kubernetes

default failReadOnlyRootFilesystem := false

# getReadOnlyRootFilesystemContainers returns all containers that have
# securityContext.readOnlyFilesystem set to true.
getReadOnlyRootFilesystemContainers contains container if {
        container := kubernetes.containers[_]
        container.securityContext.readOnlyRootFilesystem == true
}

getReadOnlyRootFilesystemContainers contains container if {
        container := kubernetes.initContainers[_]
        container.securityContext.readOnlyRootFilesystem == true
}

getReadOnlyRootFilesystemContainers contains container if {
        container := kubernetes.ephemeralContainers[_]
        container.securityContext.readOnlyRootFilesystem == true
}

getNotReadOnlyRootFilesystemContainers contains container if {
        container := kubernetes.containers[_]
        not getReadOnlyRootFilesystemContainers[container]
}

getNotReadOnlyRootFilesystemContainers contains container if {
        container := kubernetes.initContainers[_]
        not getReadOnlyRootFilesystemContainers[container]
}

getNotReadOnlyRootFilesystemContainers contains container if {
        container := kubernetes.ephemeralContainers[_]
        not getReadOnlyRootFilesystemContainers[container]
}
deny contains res if {
	output := getNotReadOnlyRootFilesystemContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.readOnlyRootFilesystem' to true", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
