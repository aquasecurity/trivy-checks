# METADATA
# title: "Workloads in the default namespace"
# description: "Checks whether a workload is running in the default namespace."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
# custom:
#   id: KSV110
#   avd_id: AVD-KSV-0110
#   severity: LOW
#   short_code: default-namespace-should-not-be-used
#   recommended_action: "Set 'metadata.namespace' to a non-default namespace."
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
package builtin.kubernetes.KSV110

import rego.v1

import data.lib.cloud.metadata
import data.lib.kubernetes

default defaultNamespaceInUse := false

allowedKinds := ["pod", "replicaset", "replicationcontroller", "deployment", "statefulset", "daemonset", "cronjob", "job"]

defaultNamespaceInUse if {
	kubernetes.namespace == "default"
	lower(kubernetes.kind) == allowedKinds[_]
}

deny contains res if {
	defaultNamespaceInUse
	msg := kubernetes.format(sprintf("%s %s in %s namespace should set metadata.namespace to a non-default namespace", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, metadata.obj_by_path(input.metadata, ["namespace"]))
}
