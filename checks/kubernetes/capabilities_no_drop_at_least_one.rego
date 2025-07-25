# METADATA
# title: "Default capabilities: some containers do not drop any"
# description: "Security best practices require containers to run with minimal required capabilities."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubesec.io/basics/containers-securitycontext-capabilities-drop-index-all/
# custom:
#   id: KSV-0004
#   aliases:
#     - AVD-KSV-0004
#     - KSV004
#     - drop-unused-capabilities
#   long_id: kubernetes-drop-unused-capabilities
#   severity: LOW
#   recommended_action: "Specify at least one unneeded capability in 'containers[].securityContext.capabilities.drop'"
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
package builtin.kubernetes.KSV004

import rego.v1

import data.lib.kubernetes
import data.lib.utils

default failCapsDropAny := false

# getCapsDropAnyContainers returns names of all containers
# which set securityContext.capabilities.drop
getCapsDropAnyContainers contains container if {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.securityContext.capabilities, "drop")
	container := allContainers.name
}

# getNoCapsDropContainers returns names of all containers which
# do not set securityContext.capabilities.drop
getNoCapsDropContainers contains container if {
	container := kubernetes.containers[_]
	not getCapsDropAnyContainers[container.name]
}

deny contains res if {
	container := getNoCapsDropContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of '%s' '%s' in '%s' namespace should set securityContext.capabilities.drop", [container.name, lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, container)
}
