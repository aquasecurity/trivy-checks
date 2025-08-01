# METADATA
# title: "Specific capabilities added"
# description: "According to pod security standard 'Capabilities', capabilities beyond the default set must not be added."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV-0022
#   aliases:
#     - AVD-KSV-0022
#     - KSV022
#     - no-non-default-capabilities
#   long_id: kubernetes-no-non-default-capabilities
#   severity: MEDIUM
#   recommended_action: "Do not set spec.containers[*].securityContext.capabilities.add and spec.initContainers[*].securityContext.capabilities.add."
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
#   examples: checks/kubernetes/specific_capabilities_added.yaml
package builtin.kubernetes.KSV022

import rego.v1

import data.lib.kubernetes

default failAdditionalCaps := false

# Add allowed capabilities to this set
allowed_caps := set()

# getContainersWithDisallowedCaps returns a list of containers which have
# additional capabilities not included in the allowed capabilities list
getContainersWithDisallowedCaps contains container if {
	container := kubernetes.containers[_]
	set_caps := {cap | cap := container.securityContext.capabilities.add[_]}
	caps_not_allowed := set_caps - allowed_caps
	count(caps_not_allowed) > 0
}

# cap_msg is a string of allowed capabilities to be print as part of deny message
caps_msg := "" if {
	count(allowed_caps) == 0
} else := msg if {
	msg := sprintf(" or set it to the following allowed values: %s", [concat(", ", allowed_caps)])
}

deny contains res if {
	output := getContainersWithDisallowedCaps[_]
	msg := sprintf("Container '%s' of %s '%s' should not set 'securityContext.capabilities.add'%s", [output.name, kubernetes.kind, kubernetes.name, caps_msg])
	res := result.new(msg, output)
}
