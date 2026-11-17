package builtin.kubernetes.KSV016

import rego.v1

import data.lib.test

test_memory_requests_not_specified_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-memory-requests"},
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
	r[_].msg == "Container 'hello' of Pod 'hello-memory-requests' should set 'resources.requests.memory'"
}

test_memory_requests_specified_allowed if {
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
			"resources": {"requests": {"memory": "64Mi"}},
		}]},
	}

	count(r) == 0
}

test_memory_requests_not_specified_ephemeral_container_skipped if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-memory-requests"},
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

	test.assert_equal_message("Container 'hello' of Pod 'hello-memory-requests' should set 'resources.requests.memory'", r)
}
