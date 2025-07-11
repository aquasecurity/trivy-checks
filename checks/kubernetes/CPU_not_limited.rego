# METADATA
# title: "CPU not limited"
# description: "Enforcing CPU limits prevents DoS via resource exhaustion."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits
# custom:
#   id: KSV-0011
#   aliases:
#     - AVD-KSV-0011
#     - KSV011
#     - limit-cpu
#   long_id: kubernetes-limit-cpu
#   severity: LOW
#   recommended_action: "Set a limit value under 'containers[].resources.limits.cpu'."
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
package builtin.kubernetes.KSV011

import rego.v1

import data.lib.kubernetes
import data.lib.utils

default failLimitsCPU := false

# getLimitsCPUContainers returns all containers which have set resources.limits.cpu
getLimitsCPUContainers contains container if {
	container := kubernetes.containers[_]
	utils.has_key(container.resources.limits, "cpu")
}

# getNoLimitsCPUContainers returns all containers which have not set
# resources.limits.cpu
getNoLimitsCPUContainers contains container if {
	container := kubernetes.containers[_]
	not getLimitsCPUContainers[container]
}

deny contains res if {
	output := getNoLimitsCPUContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'resources.limits.cpu'", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
