package builtin.kubernetes.KCV0017

import rego.v1

test_secure_port_is_set_to_zero if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver", "--advertise-address=192.168.49.2", "--secure-port=0"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --secure-port argument is not set to 0"
}

test_secure_port_is_not_set_to_zero if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver", "--advertise-address=192.168.49.2", "--secure-port=2", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_secure_port_is_not_set_to_zero_args if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver"],
			"args": ["--advertise-address=192.168.49.2", "--secure-port=2", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_secure_port_is_not_configured if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "apiserver",
			"labels": {
				"component": "kube-apiserver",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-apiserver", "--advertise-address=192.168.49.2", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}
