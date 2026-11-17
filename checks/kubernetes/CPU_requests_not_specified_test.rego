package builtin.kubernetes.KSV015

import rego.v1

import data.lib.test

test_CPU_requests_not_specified_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-cpu-request"},
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
	r[_].msg == "Container 'hello' of Pod 'hello-cpu-request' should set 'resources.requests.cpu'"
}

test_CPU_requests_specified_allowed if {
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
			"resources": {"requests": {"cpu": "250m"}},
		}]},
	}

	count(r) == 0
}

test_CPU_requests_not_specified_ephemeral_container_skipped if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-cpu-request"},
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

	test.assert_equal_message("Container 'hello' of Pod 'hello-cpu-request' should set 'resources.requests.cpu'", r)
}
