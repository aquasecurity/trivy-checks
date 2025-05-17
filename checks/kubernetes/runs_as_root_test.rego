package builtin.kubernetes.KSV012

import rego.v1

test_run_as_non_root_not_set_to_true_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-root"},
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
	r[_].msg == "Container 'hello' of Pod 'hello-run-as-root' should set 'securityContext.runAsNonRoot' to true"
}

test_run_as_non_root_not_set_to_true_for_all_containers_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-root"},
		"spec": {"containers": [
			{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
				"securityContext": {"runAsNonRoot": true},
			},
			{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello2",
			},
		]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello2' of Pod 'hello-run-as-root' should set 'securityContext.runAsNonRoot' to true"
}

test_run_as_non_root_set_to_true_for_pod_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-root"},
		"spec": {
			"securityContext": {"runAsNonRoot": true},
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

test_run_as_non_root_set_to_true_for_container_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-root"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"runAsNonRoot": true},
		}]},
	}

	count(r) == 0
}
