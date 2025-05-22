package builtin.kubernetes.KSV017

import rego.v1

test_privileged_is_true_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-privileged"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"privileged": true},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-privileged' should set 'securityContext.privileged' to false"
}

test_privileged_is_undefined_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-privileged"},
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

	count(r) == 0
}

test_privileged_is_false_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-privileged"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"privileged": false},
		}]},
	}

	count(r) == 0
}
