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
package builtin.kubernetes.KSV030

import rego.v1

import data.lib.kubernetes
import data.lib.utils

get_seccomp_profile_type(target) := object.get(target, ["securityContext", "seccompProfile", "type"], "")

is_valid_profile_type(target) if get_seccomp_profile_type(target) in {"RuntimeDefault", "Localhost"}

is_undefined_profile_type(target) if not is_defined_profile_type(target)

is_defined_profile_type(target) if get_seccomp_profile_type(target) != ""

get_annotations contains type if {
	annotation := kubernetes.annotations[_]
	type := annotation["seccomp.security.alpha.kubernetes.io/pod"]
}

has_annotations if count(get_annotations) > 0

fail_seccomp_annotation contains annotation if {
	some annotation in kubernetes.annotations
	val := annotation["seccomp.security.alpha.kubernetes.io/pod"]
	val != "runtime/default"
}

# annotations (Kubernetes pre-v1.19)
deny contains res if {
	some cause in fail_seccomp_annotation
	msg := "seccomp.security.alpha.kubernetes.io/pod should be set to 'runtime/default'"
	res := result.new(msg, cause)
}

# (Kubernetes post-v1.19)

is_defined_on_pod if count(definedPods) > 0

definedPods := {pod |
	some pod in kubernetes.pods
	not is_undefined_profile_type(pod.spec)
}

# deny if container-level is undefined and pod-level is undefined
deny contains res if {
	not has_annotations
	not is_defined_on_pod
	container := kubernetes.containers[_]
	is_undefined_profile_type(container)
	msg := "Either Pod or Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'"
	res := result.new(msg, container)
}

# deny if container-level is bad
deny contains res if {
	container := kubernetes.containers[_]
	not is_undefined_profile_type(container)
	not is_valid_profile_type(container)
	msg := "Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'"
	res := result.new(msg, container)
}

# deny if pod-level is bad
deny contains res if {
	pod := kubernetes.pods[_]
	not is_undefined_profile_type(pod.spec)
	not is_valid_profile_type(pod.spec)
	msg := "Pod should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'"
	res := result.new(msg, pod.spec)
}
