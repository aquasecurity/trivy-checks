package builtin.kubernetes.KSV118

import rego.v1

test_container_inherit_security_context if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "pod-with-default-container"},
		"spec": {
			"securityContext": {"runAsUser": 1001},
			"containers": [{
				"name": "default-container",
				"image": "busybox",
				"securityContext": {},
			}],
		},
	}

	count(r) == 0
}

test_pod_and_container_without_security_context if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "pod-with-default-container"},
		"spec": {"containers": [{
			"name": "default-container",
			"image": "busybox",
		}]},
	}

	count(r) == 2
}

test_deployment_without_security_context if {
	r := deny with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {"name": "my-app"},
		"spec": {
			"replicas": 3,
			"selector": {"matchLabels": {"app": "my-app"}},
			"template": {
				"metadata": {"labels": {"app": "my-app"}},
				"spec": {"containers": [{
					"name": "my-app-container",
					"image": "nginx:latest",
					"ports": [{"containerPort": 80}],
					"securityContext": {"runAsUser": 1001},
				}]},
			},
		},
	}

	count(r) == 1
}

test_deployment_with_empty_security_context if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "pod-with-non-default-container"},
		"spec": {
			"securityContext": {"__defsec_metadata": {}},
			"containers": [{
				"name": "non-default-container",
				"image": "busybox",
				"securityContext": {"runAsUser": 1001},
			}],
		},
	}

	count(r) == 1
}

test_container_with_non_default_security_context if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "pod-with-non-default-container"},
		"spec": {
			"securityContext": {"runAsUser": 1001},
			"containers": [{
				"name": "non-default-container",
				"image": "busybox",
				"securityContext": {"runAsUser": 1001},
			}],
		},
	}

	# Assert that the result should be empty because security context is non-default
	count(r) == 0
}
