package builtin.kubernetes.KCV0010

import rego.v1

test_event_rate_limit_plugin_is_enabled if {
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
			"command": ["kube-apiserver", "--enable-admission-plugins=EventRateLimit"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_event_rate_limit_plugin_is_not_configured if {
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
			"command": ["kube-apiserver", "--authorization-mode=Node,RBAC", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the admission control plugin EventRateLimit is set"
}

test_event_rate_limit_plugin_is_not_enabled if {
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
			"command": ["kube-apiserver", "--enable-admission-plugins=NamespaceLifecycle,ServiceAccount"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the admission control plugin EventRateLimit is set"
}

test_event_rate_limit_plugin_is_enabled_with_others if {
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
			"command": ["kube-apiserver", "--enable-admission-plugins=NamespaceLifecycle,EventRateLimit,ServiceAccount"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_event_rate_limit_plugin_is_enabled_with_others_args if {
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
			"args": ["--enable-admission-plugins=NamespaceLifecycle,EventRateLimit,ServiceAccount"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}
