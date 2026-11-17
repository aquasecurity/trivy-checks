package builtin.kubernetes.KSV027

import rego.v1

import data.lib.test

test_proc_mount_is_set_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-proc-mount"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"ports": [{"hostPort": 8080}],
			"securityContext": {"procMount": "Unmasked"},
		}]},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-proc-mount' should not set 'spec.containers[*].securityContext.procMount', 'spec.initContainers[*].securityContext.procMount' or 'spec.ephemeralContainers[*].securityContext.procMount'"
}

test_proc_mount_is_not_set_allowed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-proc-mount"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"ports": [{"hostPort": 8080}],
			"securityContext": {},
		}]},
	}

	count(r) == 0
}

test_proc_mount_is_set_in_ephemeral_container_denied if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-proc-mount"},
		"spec": {
			"containers": [{
				"image": "busybox",
				"name": "hello",
			}],
			"ephemeralContainers": [{
				"image": "busybox",
				"name": "debugger",
				"securityContext": {"procMount": "Unmasked"},
			}],
		},
	}

	test.assert_equal_message("Pod 'hello-proc-mount' should not set 'spec.containers[*].securityContext.procMount', 'spec.initContainers[*].securityContext.procMount' or 'spec.ephemeralContainers[*].securityContext.procMount'", r)
}
