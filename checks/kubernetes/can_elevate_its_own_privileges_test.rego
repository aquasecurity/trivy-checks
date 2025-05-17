package builtin.kubernetes.KSV001

import rego.v1

test_allow_privilege_escalation_set_to_false_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-privilege-escalation"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"allowPrivilegeEscalation": false},
		}]},
	}

	count(r) == 0
}

test_allow_privilege_escalation_is_undefined_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-privilege-escalation"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-privilege-escalation' should set 'securityContext.allowPrivilegeEscalation' to false"
}

test_allow_privilege_escalation_set_to_true_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-privilege-escalation"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"allowPrivilegeEscalation": true},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-privilege-escalation' should set 'securityContext.allowPrivilegeEscalation' to false"
}

test_allow_privilege_escalation_multiple_containers if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-privilege-escalation"},
		"spec": {"containers": [
			{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
				"securityContext": {"allowPrivilegeEscalation": true},
			},
			{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello2",
				"securityContext": {"allowPrivilegeEscalation": false},
			},
		]},
	}
	count(r) == 1
}
