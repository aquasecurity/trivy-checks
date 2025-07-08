# METADATA
# title: "Default security context configured"
# description: "Security context controls the allocation of security parameters for the pod/container/volume, ensuring the appropriate level of protection. Relying on default security context may expose vulnerabilities to potential attacks that rely on privileged access."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
# custom:
#   id: KSV-0118
#   aliases:
#     - AVD-KSV-0118
#     - KSV118
#     - no-default-security-context
#   long_id: kubernetes-no-default-security-context
#   severity: HIGH
#   recommended_action: "To enhance security, it is strongly recommended not to rely on the default security context. Instead, it is advisable to explicitly define the required security parameters (such as runAsNonRoot, capabilities, readOnlyRootFilesystem, etc.) within the security context."
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
package builtin.kubernetes.KSV118

import rego.v1

import data.lib.kubernetes

deny contains res if {
	some pod in kubernetes.pods
	is_empty(object.get(pod, ["spec", "securityContext"], {}))
	msg := kubernetes.format(sprintf(
		"%s %s in %s namespace is using the default security context, which allows root privileges",
		[lower(kubernetes.kind), kubernetes.name, kubernetes.namespace],
	))
	res := result.new(msg, object.get(pod, "spec", pod))
}

deny contains res if {
	some container in kubernetes.containers
	is_empty(object.get(container, ["securityContext"], {}))
	msg := kubernetes.format(sprintf(
		"container %s in %s namespace is using the default security context",
		[kubernetes.name, kubernetes.namespace],
	))
	res := result.new(msg, container)
}

is_empty(obj) if obj == {}
is_empty(obj) if object.keys(obj) == {"__defsec_metadata"}
