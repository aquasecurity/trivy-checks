# METADATA
# title: "NET_RAW capability added"
# description: "The NET_RAW capability grants attackers the ability to eavesdrop on network traffic or generate IP traffic with falsified source addresses, posing serious security risks."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/
# custom:
#   id: KSV-0119
#   long_id: kubernetes-no-net-raw
#   aliases:
#     - AVD-KSV-0119
#     - KSV119
#     - no-net-raw
#     - kubernetes-no-net-raw
#   severity: HIGH
#   recommended_action: "To mitigate potential security risks, it is strongly recommended to remove the NET_RAW capability from 'containers[].securityContext.capabilities.add'. It is advisable to follow the practice of dropping all capabilities and only adding the necessary ones."
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
package builtin.kubernetes.KSV119

import rego.v1

import data.lib.kubernetes

default failCapsNetRaw := false

# getCapsNetRaw returns all containers which include
# 'NET_RAW' in securityContext.capabilities.add.
getCapsNetRaw contains container if {
	container := kubernetes.containers[_]
	container.securityContext.capabilities.add[_] == "NET_RAW"
}

deny contains res if {
	container := getCapsNetRaw[_]
	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should not include 'NET_RAW' in securityContext.capabilities.add", [container.name, lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, container)
}
