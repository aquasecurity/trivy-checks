package builtin.kubernetes.KSV009

import rego.v1

test_host_network_set_to_true_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-host-network"},
		"spec": {
			"hostNetwork": true,
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

	count(r) == 1
	r[_].msg == "Pod 'hello-host-network' should not set 'spec.template.spec.hostNetwork' to true"
}

test_host_network_set_to_false_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-host-network"},
		"spec": {
			"hostNetwork": false,
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

	count(r) == 0
}

test_host_network_is_undefined_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-host-network"},
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
