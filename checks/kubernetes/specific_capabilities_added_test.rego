package builtin.kubernetes.KSV022

import rego.v1

import data.lib.test

test_capabilities_add_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-add-capabilities"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"add": ["NET_BIND_SERVICE"]}},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-add-capabilities' should not set 'securityContext.capabilities.add'"
}

test_capabilities_add_empty_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-add-capabilities"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"add": []}},
		}]},
	}

	count(r) == 0
}

test_capabilities_no_add_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-add-capabilities"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {}},
		}]},
	}

	count(r) == 0
}

test_no_capabilities_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-add-capabilities"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {},
		}]},
	}

	count(r) == 0
}

test_capabilities_add_in_ephemeral_container_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-add-capabilities"},
		"spec": {
			"containers": [{
				"image": "busybox",
				"name": "hello",
			}],
			"ephemeralContainers": [{
				"image": "busybox",
				"name": "debugger",
				"securityContext": {"capabilities": {"add": ["SYS_PTRACE"]}},
			}],
		},
	}

	test.assert_equal_message("Container 'debugger' of Pod 'hello-add-capabilities' should not set 'securityContext.capabilities.add'", r)
}
