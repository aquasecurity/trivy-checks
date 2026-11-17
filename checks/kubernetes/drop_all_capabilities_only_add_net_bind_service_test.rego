package builtin.kubernetes.KSV106

import rego.v1

test_drop_all_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-seccomp"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"drop": ["ALL"]}},
		}]},
	}

	count(r) == 0
}

test_drop_all_add_net_bind_service_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-seccomp"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"drop": ["all"], "add": ["NET_BIND_SERVICE"]}},
		}]},
	}

	count(r) == 0
}

test_drop_all_and_more_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-seccomp"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"drop": ["something", "ALL", "other"]}},
		}]},
	}

	count(r) == 0
}

test_drop_other_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-seccomp"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"drop": ["OTHER"]}},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' does not drop all capabilities"
}

test_drop_undefined_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-seccomp"},
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
	r[_].msg == "Container 'hello' does not drop all capabilities"
}

test_drop_all_add_other_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-seccomp"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"drop": ["ALL"], "add": ["SOMETHING"]}},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' adds disallowed capabilities: SOMETHING"
}

test_drop_all_add_multiple_disallowed_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-seccomp"},
		"spec": {"containers": [{
			"command": ["sh", "-c", "echo 'Hello' && sleep 1h"],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"drop": ["ALL"], "add": ["SYS_ADMIN", "NET_RAW"]}},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' adds disallowed capabilities: NET_RAW, SYS_ADMIN"
}

test_drop_all_add_net_bind_service_and_disallowed_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-seccomp"},
		"spec": {"containers": [{
			"command": ["sh", "-c", "echo 'Hello' && sleep 1h"],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"drop": ["ALL"], "add": ["NET_BIND_SERVICE", "SYS_ADMIN"]}},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' adds disallowed capabilities: SYS_ADMIN"
}