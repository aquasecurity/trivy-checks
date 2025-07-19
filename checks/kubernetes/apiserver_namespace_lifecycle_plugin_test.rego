package builtin.kubernetes.KCV0015

import rego.v1

test_namespace_lifecycle_plugin_is_disabled if {
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
			"command": ["kube-apiserver", "--disable-admission-plugins=AlwaysAdmit,NamespaceLifecycle"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the admission control plugin NamespaceLifecycle is set"
}

test_namespace_lifecycle_plugin_is_not_disabled if {
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
			"command": ["kube-apiserver", "--disable-admission-plugins=AlwaysAdmit"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_namespace_lifecycle_plugin_is_not_disabled_args if {
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
			"args": ["--disable-admission-plugins=AlwaysAdmit"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}
