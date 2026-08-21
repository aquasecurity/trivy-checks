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
}
test_drop_all_denied_init_container if {
        r := deny with input as {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "hello-seccomp"},
                "spec": {"initContainers": [{
                        "image": "busybox",
                        "name": "hello-init",
                        "securityContext": {"capabilities": {"drop": ["OTHER"]}},
                }]},
        }

        count(r) == 1
}

test_drop_all_allowed_init_container if {
        r := deny with input as {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "hello-seccomp"},
                "spec": {"initContainers": [{
                        "image": "busybox",
                        "name": "hello-init",
                        "securityContext": {"capabilities": {"drop": ["ALL"]}},
                }]},
        }

        count(r) == 0
}

test_drop_all_denied_ephemeral_container if {
        r := deny with input as {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "hello-seccomp"},
                "spec": {"ephemeralContainers": [{
                        "image": "busybox",
                        "name": "hello-ephemeral",
                        "securityContext": {"capabilities": {"drop": ["OTHER"]}},
                }]},
        }

        count(r) == 1
}

test_drop_all_allowed_ephemeral_container if {
        r := deny with input as {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "hello-seccomp"},
                "spec": {"ephemeralContainers": [{
                        "image": "busybox",
                        "name": "hello-ephemeral",
                        "securityContext": {"capabilities": {"drop": ["ALL"]}},
                }]},
        }

        count(r) == 0
}