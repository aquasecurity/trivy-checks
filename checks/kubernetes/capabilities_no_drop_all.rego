# METADATA
# title: "Default capabilities: some containers do not drop all"
# description: "The container should drop all default capabilities and add only those that are needed for its execution."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubesec.io/basics/containers-securitycontext-capabilities-drop-index-all/
# custom:
#   id: KSV003
#   avd_id: AVD-KSV-0003
#   severity: LOW
#   short_code: drop-default-capabilities
#   recommended_action: "Add 'ALL' to containers[].securityContext.capabilities.drop."
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
package builtin.kubernetes.KSV003

import rego.v1

import data.lib.kubernetes

default checkCapsDropAll := false

# Get all containers which include 'ALL' in security.capabilities.drop
getCapsDropAllContainers contains container if {
	allContainers := kubernetes.containers[_]
	lower(allContainers.securityContext.capabilities.drop[_]) == "all"
	container := allContainers.name
}

# Get all containers which don't include 'ALL' in security.capabilities.drop
getCapsNoDropAllContainers contains container if {
	container := kubernetes.containers[_]
	not getCapsDropAllContainers[container.name]
}

deny contains res if {
	container := getCapsNoDropAllContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should add 'ALL' to 'securityContext.capabilities.drop'", [container.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, container)
}
