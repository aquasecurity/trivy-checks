package builtin.kubernetes.KCV0041

import rego.v1

test_bind_address_is_set_to_localhost_ip if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "scheduler",
			"labels": {
				"component": "kube-scheduler",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-scheduler", "--authentication-kubeconfig=<path/to/file>", "--bind-address=127.0.0.1"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_bind_address_is_set_to_localhost_ip_args if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "scheduler",
			"labels": {
				"component": "kube-scheduler",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-scheduler"],
			"args": ["--authentication-kubeconfig=<path/to/file>", "--bind-address=127.0.0.1"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_bind_address_is_set_to_different_ip if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "scheduler",
			"labels": {
				"component": "kube-scheduler",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-scheduler", "--authentication-kubeconfig=<path/to/file>", "--bind-address=192.168.0.1"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --bind-address argument is set to 127.0.0.1"
}

test_bind_address_is_not_configured if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "scheduler",
			"labels": {
				"component": "kube-scheduler",
				"tier": "control-plane",
			},
		},
		"spec": {"containers": [{
			"command": ["kube-scheduler", "--authentication-kubeconfig=<path/to/file>", "--profiling=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --bind-address argument is set to 127.0.0.1"
}
