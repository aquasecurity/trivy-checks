package builtin.kubernetes.KCV0008

import rego.v1

test_authorization_mode_is_set_node if {
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
			"command": ["kube-apiserver", "--authorization-mode=Node", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_authorization_mode_includes_node if {
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
			"command": ["kube-apiserver", "--authorization-mode=RBAC,Node", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_authorization_mode_includes_node_args if {
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
			"args": ["--authorization-mode=RBAC,Node", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_authorization_mode_default_value if {
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
			"command": ["kube-apiserver", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --authorization-mode argument includes Node"
}

test_authorization_mode_is_set_rbac if {
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
			"command": ["kube-apiserver", "--authorization-mode=RBAC", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --authorization-mode argument includes Node"
}

test_authorization_mode_with_multiple_values if {
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
			"command": ["kube-apiserver", "--authorization-mode=ABAC,Webhook,AlwaysAllow", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --authorization-mode argument includes Node"
}
