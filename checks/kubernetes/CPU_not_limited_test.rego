package builtin.kubernetes.KSV011

import rego.v1

import data.lib.test

test_CPU_not_limited_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-cpu-limit"},
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
	r[_].msg == "Container 'hello' of Pod 'hello-cpu-limit' should set 'resources.limits.cpu'"
}

test_CPU_limited_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-cpu-limit"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"resources": {"limits": {"cpu": "500m"}},
		}]},
	}

	count(r) == 0
}

test_CPU_not_limited_ephemeral_container_skipped if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-cpu-limit"},
		"spec": {
			"containers": [{
				"image": "busybox",
				"name": "hello",
			}],
			"ephemeralContainers": [{
				"image": "busybox",
				"name": "debugger",
			}],
		},
	}

	test.assert_equal_message("Container 'hello' of Pod 'hello-cpu-limit' should set 'resources.limits.cpu'", r)
}
