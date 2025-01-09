package builtin.kubernetes.KCV0047

import rego.v1

test_peer_auto_tls_is_set_to_false if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd", "--advertise-client-urls=https://192.168.49.2:2379", "--peer-auto-tls=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_peer_auto_tls_is_set_to_false_args if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd"],
			"args": ["--advertise-client-urls=https://192.168.49.2:2379", "--peer-auto-tls=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_peer_auto_tls_is_set_to_true if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd", "--advertise-client-urls=https://192.168.49.2:2379", "--peer-auto-tls=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --peer-auto-tls argument is not set to true"
}

test_peer_auto_tls_is_not_configured if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "etcd",
			"labels": {
				"component": "etcd",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["etcd", "--advertise-client-urls=https://192.168.49.2:2379", "--cert-file=<filename>"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}
