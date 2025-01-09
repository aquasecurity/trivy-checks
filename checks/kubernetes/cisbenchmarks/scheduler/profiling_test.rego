package builtin.kubernetes.KCV0040

import rego.v1

test_profiling_is_set_to_false if {
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

	count(r) == 0
}

test_profiling_is_set_to_false_args if {
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
			"args": ["--authentication-kubeconfig=<path/to/file>", "--profiling=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_profiling_is_set_to_true if {
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
			"command": ["kube-scheduler", "--authentication-kubeconfig=<path/to/file>", "--profiling=true"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --profiling argument is set to false"
}

test_profiling_is_not_configured if {
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
			"command": ["kube-scheduler", "--authentication-kubeconfig=<path/to/file>"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --profiling argument is set to false"
}
