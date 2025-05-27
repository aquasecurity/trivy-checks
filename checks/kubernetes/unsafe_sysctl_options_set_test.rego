package builtin.kubernetes.KSV026

import rego.v1

test_sysctls_restricted_property_denied if {
	r := deny with input as build_pod({"sysctls": [
		{
			"name": "net.core.somaxconn",
			"value": "1024",
		},
		{
			"name": "kernel.msgmax",
			"value": "65536",
		},
	]})

	count(r) == 1
	r[_].msg == "Pod 'hello-sysctls' has disallowed sysctls: [\"kernel.msgmax\", \"net.core.somaxconn\"] and must only use allowed sysctls."
}

test_sysctls_not_restricted_property_mixed_with_restriced_denied if {
	r := deny with input as build_pod({"sysctls": [
		{
			"name": "kernel.shm_rmid_forced",
			"value": "0",
		},
		{
			"name": "net.core.somaxconn",
			"value": "1024",
		},
		{
			"name": "kernel.msgmax",
			"value": "65536",
		},
	]})

	count(r) == 1
	r[_].msg == "Pod 'hello-sysctls' has disallowed sysctls: [\"kernel.msgmax\", \"net.core.somaxconn\"] and must only use allowed sysctls."
}

test_sysctls_not_restricted_property_allowed if {
	r := deny with input as build_pod({"sysctls": [{
		"name": "kernel.shm_rmid_forced",
		"value": "0",
	}]})

	count(r) == 0
}

test_sysctls_is_undefined_allowed if {
	r := deny with input as build_pod({})

	count(r) == 0
}

test_deny_sysctl_not_allowed_in_1_29 if {
	r := deny with input as build_pod({"sysctls": [{"name": "net.ipv4.tcp_wmem"}]})
		with data.k8s.version as "1.29.0"

	count(r) == 1
	r[_].msg == "Pod 'hello-sysctls' has disallowed sysctls: [\"net.ipv4.tcp_wmem\"] and must only use allowed sysctls."
}

test_allow_sysctl_in_1_33_rc if {
	r := deny with input as build_pod({"sysctls": [{"name": "net.ipv4.tcp_wmem"}]})
		with data.k8s.version as "1.33.0-rc.1"

	count(r) == 0
}

test_allow_sysctl_in_1_32_patch_gke if {
	r := deny with input as build_pod({"sysctls": [{"name": "net.ipv4.tcp_wmem"}]})
		with data.k8s.version as "1.32.2-gke.1182001"

	count(r) == 0
}

test_allow_sysctl_with_invalid_semver if {
	r := deny with input as build_pod({"sysctls": [{"name": "net.ipv4.tcp_wmem"}]})
		with data.k8s.version as "1.29"

	count(r) == 0
}

build_pod(sc) := {
	"apiVersion": "v1",
	"kind": "Pod",
	"metadata": {"name": "hello-sysctls"},
	"spec": {
		"securityContext": sc,
		"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
		}],
	},
}
