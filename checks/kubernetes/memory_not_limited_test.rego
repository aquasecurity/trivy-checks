package builtin.kubernetes.KSV018

import rego.v1

import data.lib.test

test_memory_not_limited_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-memory-limit"},
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
	r[_].msg == "Container 'hello' of Pod 'hello-memory-limit' should set 'resources.limits.memory'"
}

test_memory_limited_allowed if {
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
			"resources": {"limits": {"memory": "128Mi"}},
		}]},
	}

	count(r) == 0
}

test_memory_not_limited_ephemeral_container_skipped if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-memory-limit"},
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

	test.assert_equal_message("Container 'hello' of Pod 'hello-memory-limit' should set 'resources.limits.memory'", r)
}
