# METADATA
# title: "Unsafe sysctl options set"
# description: "Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed 'safe' subset. A sysctl is considered safe if it is namespaced in the container or the Pod, and it is isolated from other Pods or processes on the same Node."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# custom:
#   id: KSV026
#   avd_id: AVD-KSV-0026
#   severity: MEDIUM
#   short_code: no-unsafe-sysctl
#   recommended_action: "Do not set 'spec.securityContext.sysctls' or set to values in an allowed subset"
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
#   examples: checks/kubernetes/unsafe_sysctl_options_set.yaml
package builtin.kubernetes.KSV026

import rego.v1

import data.k8s
import data.lib.kubernetes

sysctls_1_0 := {
	"kernel.shm_rmid_forced",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.ip_unprivileged_port_start",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ping_group_range",
}

sysctls_1_27 := sysctls_1_0 | {"net.ipv4.ip_local_reserved_ports"}

sysctls_1_29 := sysctls_1_27 | {
	"net.ipv4.tcp_keepalive_time",
	"net.ipv4.tcp_fin_timeout",
	"net.ipv4.tcp_keepalive_intvl",
	"net.ipv4.tcp_keepalive_probes",
}

sysctls_1_32 := sysctls_1_29 | {
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
}

# Mapping of Kubernetes versions to allowed sysctls based on on Kubernetes PodSecurity "baseline" policy.
# See: https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# Source (commit 44c230b):
# https://github.com/kubernetes/kubernetes/blob/44c230bf5c321056e8bc89300b37c497f464f113/staging/src/k8s.io/pod-security-admission/policy/check_sysctls.go#L39-L51
sysctls_matrix := {
	"1.0.0": sysctls_1_0,
	"1.27.0": sysctls_1_27,
	"1.29.0": sysctls_1_29,
	"1.32.0": sysctls_1_32,
}

versions := object.keys(sysctls_matrix)

allowed_sysctls := sysctls_matrix[max_ver] if {
	candidates := [ver |
		some ver in versions
		semver.compare(k8s.version, ver) >= 0
	]
	count(candidates) > 0
	max_ver := max(candidates)
} else := sysctls_1_32

disallowed_sysctls(pod) := disallowed if {
	requested_sysctls := {s.name | some s in pod.spec.securityContext.sysctls}
	disallowed := requested_sysctls - allowed_sysctls
}

deny contains res if {
	some pod in kubernetes.pods
	disallowed := disallowed_sysctls(pod)
	count(disallowed) > 0
	msg := sprintf(
		"Pod '%s' has disallowed sysctls: %v and must only use allowed sysctls.",
		[kubernetes.name, sort(disallowed)],
	)
	res := result.new(msg, pod)
}
