# METADATA
# title: "Runtime/Default Seccomp profile not set"
# description: "According to pod security standard 'Seccomp', the RuntimeDefault seccomp profile must be required, or allow specific additional profiles."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV030
#   avd_id: AVD-KSV-0030
#   severity: LOW
#   short_code: use-default-seccomp
#   recommended_action: "Set 'spec.securityContext.seccompProfile.type', 'spec.containers[*].securityContext.seccompProfile' and 'spec.initContainers[*].securityContext.seccompProfile' to 'RuntimeDefault' or undefined."
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
#   examples: checks/kubernetes/runtime_default_seccomp_profile_not_set.yaml
package builtin.kubernetes.KSV030

import rego.v1

import data.lib.kubernetes

seccomp_pod_annotation_key := "seccomp.security.alpha.kubernetes.io/pod"

non_runtime_default_seccomp_annotations := {annotation |
	some annotation in kubernetes.annotations
	"runtime/default" != annotation[seccomp_pod_annotation_key]
}

# annotations (Kubernetes pre-v1.19)
deny contains res if {
	some cause in non_runtime_default_seccomp_annotations
	res := result.new(
		sprintf("%s should be set to 'runtime/default'", [seccomp_pod_annotation_key]),
		cause,
	)
}

# (Kubernetes post-v1.19)

has_seccomp_annotation(pod) if pod.metadata.annotations[seccomp_pod_annotation_key]

get_seccomp_profile_type(target) := object.get(target, ["securityContext", "seccompProfile", "type"], "")

is_valid_profile_type(target) if get_seccomp_profile_type(target) in {"RuntimeDefault", "Localhost"}

# deny if container-level is undefined and pod-level is undefined
deny contains res if {
	some pod in kubernetes.pods
	not has_seccomp_annotation(pod)

	some container in kubernetes.pod_containers(pod)
	not is_valid_profile_type(container)
	msg := "Either Pod or Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'"
	res := result.new(msg, container)
}
