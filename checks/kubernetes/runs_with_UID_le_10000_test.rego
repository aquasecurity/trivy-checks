package builtin.kubernetes.KSV020

import rego.v1

test_UID_gt_10000_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-uid"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"runAsUser": 10004},
		}]},
	}

	count(r) == 0
}

test_no_run_as_user_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-uid"},
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
	r[_].msg == "Container 'hello' of Pod 'hello-uid' should set 'securityContext.runAsUser' > 10000"
}

test_low_uid_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-uid"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"runAsUser": 100},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-uid' should set 'securityContext.runAsUser' > 10000"
}

test_zero_uid_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-uid"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"runAsUser": 0},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-uid' should set 'securityContext.runAsUser' > 10000"
}

test_pod_sec_ctx_low_uid_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-uid"},
		"spec": {
			"securityContext": {"runAsUser": 100},
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
	r[_].msg == "Container 'hello' of Pod 'hello-uid' should set 'securityContext.runAsUser' > 10000"
}
