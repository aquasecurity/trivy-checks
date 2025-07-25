# METADATA
# title: "Seccomp policies disabled"
# description: "A program inside the container can bypass Seccomp protection policies."
# scope: package
# schemas:
#   - input: schema["kubernetes"]
# related_resources:
#   - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV-0104
#   aliases:
#     - AVD-KSV-0104
#     - KSV104
#     - no-seccomp-unconfined
#   long_id: kubernetes-no-seccomp-unconfined
#   severity: MEDIUM
#   recommended_action: "Specify seccomp either by annotation or by seccomp profile type having allowed values as per pod security standards"
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
package builtin.kubernetes.KSV104

import rego.v1

import data.lib.kubernetes

pod_seccomp_profile_path := ["securityContext", "seccompProfile", "type"]

controller_seccomp_profile_path := ["spec", "securityContext", "seccompProfile", "type"]

seccomp_annotation_key_prefix := "container.seccomp.security.alpha.kubernetes.io"

container_seccomp_annotation_key(container_name) := sprintf("%s/%s", [seccomp_annotation_key_prefix, container_name])

container_seccomp_from_annotations(container) := profile if {
	annotation_key := container_seccomp_annotation_key(container.name)
	profile := kubernetes.annotations[_][annotation_key]
} else := ""

# containers_with_unconfined_seccomp_profile_type returns all containers which have a seccomp
# profile set and is profile set to "Unconfined"
containers_with_unconfined_seccomp_profile_type contains seccomp.container if {
	seccomp := container_seccomp[_]
	lower(seccomp.type) == "unconfined"
}

# containers_with_unconfined_seccomp_profile_type returns all containers that do not have
# a seccomp profile type specified, since the default is unconfined
# https://kubernetes.io/docs/tutorials/security/seccomp/#enable-the-use-of-runtimedefault-as-the-default-seccomp-profile-for-all-workloads
containers_with_unconfined_seccomp_profile_type contains seccomp.container if {
	seccomp := container_seccomp[_]
	seccomp.type == ""
}

container_seccomp contains {"container": container, "type": type} if {
	kubernetes.is_pod
	container := kubernetes.containers[_]
	profile := container_seccomp_from_annotations(container)
	type := object.get(container, pod_seccomp_profile_path, profile)
}

container_seccomp contains {"container": container, "type": type} if {
	not kubernetes.is_pod
	pod := kubernetes.pods[_]
	container := kubernetes.pod_containers(pod)[_]
	profile := container_seccomp_from_annotations(container)

	# the profile type specified in the template takes precedence over the annotation
	tplSeccompProfile := object.get(pod, controller_seccomp_profile_path, profile)
	type := object.get(container, pod_seccomp_profile_path, tplSeccompProfile)
}

deny contains res if {
	container := containers_with_unconfined_seccomp_profile_type[_]
	msg := kubernetes.format(sprintf("container %q of %s %q in %q namespace should specify a seccomp profile", [container.name, lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, container)
}
