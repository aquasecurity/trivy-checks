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
#   examples: checks/kubernetes/security/9_unsafe_sysctl_options_set.yaml
package builtin.kubernetes.KSV026

import rego.v1

import data.lib.kubernetes

default failSysctls := false

# Allowed sysctls list based on Kubernetes PodSecurity "baseline" policy.
# See: https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
# Source (commit 44c230b):
# https://github.com/kubernetes/kubernetes/blob/44c230bf5c321056e8bc89300b37c497f464f113/staging/src/k8s.io/pod-security-admission/policy/check_sysctls.go#L39-L51
allowed_sysctls := {
	"kernel.shm_rmid_forced",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.ip_unprivileged_port_start",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ping_group_range",
	"net.ipv4.ip_local_reserved_ports",
	"net.ipv4.tcp_keepalive_time",
	"net.ipv4.tcp_fin_timeout",
	"net.ipv4.tcp_keepalive_intvl",
	"net.ipv4.tcp_keepalive_probes",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
}

# failSysctls is true if a disallowed sysctl is set
failSysctls if {
	pod := kubernetes.pods[_]
	set_sysctls := {sysctl | sysctl := pod.spec.securityContext.sysctls[_].name}
	sysctls_not_allowed := set_sysctls - allowed_sysctls
	count(sysctls_not_allowed) > 0
}

deny contains res if {
	failSysctls
	msg := kubernetes.format(sprintf("%s '%s' should set 'securityContext.sysctl' to the allowed values", [kubernetes.kind, kubernetes.name]))
	res := result.new(msg, input.spec)
}
