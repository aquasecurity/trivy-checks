package builtin.kubernetes.KCV0024

import rego.v1

test_service_account_lookup_is_false if {
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
			"command": ["kube-apiserver", "--authorization-mode=AlwaysAllow", "--service-account-lookup=false", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Ensure that the --service-account-lookup argument is set to true"
}

test_service_account_lookup_is_true if {
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
			"command": ["kube-apiserver", "--authorization-mode=AlwaysAllow", "--service-account-lookup=true", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_service_account_lookup_is_true_args if {
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
			"args": ["--authorization-mode=AlwaysAllow", "--service-account-lookup=true", "--anonymous-auth=false"],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_service_account_lookup_is_not_configured if {
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

	count(r) == 0
}
