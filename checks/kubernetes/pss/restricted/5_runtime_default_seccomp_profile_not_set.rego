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

getType(target) := type if {
	context := getOr(target, "securityContext", {})
	profile := getOr(context, "seccompProfile", {})
	type := getOr(profile, "type", "")
}

isValidProfileType(target) if {
	getType(target) == "RuntimeDefault"
}

isValidProfileType(target) if {
	getType(target) == "Localhost"
}

isUndefinedProfileType(target) if {
	not isDefinedProfileType(target)
}

getOr(obj, key, def) := res if {
	res := obj[key]
}

getOr(obj, key, def) := res if {
	not obj[key]
	res := def
}

isDefinedProfileType(target) if {
	getType(target) != ""
}

getAnnotations contains type if {
	annotation := kubernetes.annotations[_]
	type := annotation["seccomp.security.alpha.kubernetes.io/pod"]
}

hasAnnotations if {
	count(getAnnotations) > 0
}

failSeccompAnnotation contains annotation if {
	annotation := kubernetes.annotations[_]
	val := annotation["seccomp.security.alpha.kubernetes.io/pod"]
	val != "runtime/default"
}

# annotations (Kubernetes pre-v1.19)
deny contains res if {
	cause := failSeccompAnnotation[_]
	msg := "seccomp.security.alpha.kubernetes.io/pod should be set to 'runtime/default'"
	res := result.new(msg, cause)
}

# (Kubernetes post-v1.19)

isDefinedOnPod if {
	count(definedPods) > 0
}

definedPods contains pod if {
	pod := kubernetes.pods[_]
	not isUndefinedProfileType(pod.spec)
}

# deny if container-level is undefined and pod-level is undefined
deny contains res if {
	not hasAnnotations
	not isDefinedOnPod
	container := kubernetes.containers[_]
	isUndefinedProfileType(container)
	msg := "Either Pod or Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'"
	res := result.new(msg, container)
}

# deny if container-level is bad
deny contains res if {
	container := kubernetes.containers[_]
	not isUndefinedProfileType(container)
	not isValidProfileType(container)
	msg := "Container should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'"
	res := result.new(msg, container)
}

# deny if pod-level is bad
deny contains res if {
	pod := kubernetes.pods[_]
	not isUndefinedProfileType(pod.spec)
	not isValidProfileType(pod.spec)
	msg := "Pod should set 'securityContext.seccompProfile.type' to 'RuntimeDefault'"
	res := result.new(msg, pod.spec)
}
