package builtin.kubernetes.KSV104

test_container_seccomp_profile_unconfined_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {"containers": [{
			"name": "hello",
			"image": "busybox",
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"securityContext": {"seccompProfile": {"type": "Unconfined"}},
		}]},
	}

	count(r) == 1
}

test_container_empty_seccomp_profile_unconfined_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {"containers": [{
			"name": "hello",
			"image": "busybox",
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
		}]},
	}

	count(r) == 1
}

test_container_seccomp_profile_unconfined_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "my-pod"},
		"spec": {"containers": [
			{
				"name": "container-1",
				"image": "nginx",
				"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
			},
			{
				"name": "container-2",
				"image": "busybox",
				"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
			},
		]},
	}

	count(r) == 0
}

test_deployment_seccomp_profile_unconfined_allowed {
	r := deny with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "mydeployment",
			"namespace": "mynamespace",
		},
		"spec": {
			"selector": {"matchLabels": {"app": "myapp"}},
			"template": {
				"metadata": {"labels": {"app": "myapp"}},
				"spec": {
					"containers": [{
						"name": "container",
						"image": "node:8-alpine",
					}],
					"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
				},
			},
		},
	}
	count(r) == 0
}

test_deployment_seccomp_profile_unconfined_denied {
	r := deny with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "mydeployment",
			"namespace": "mynamespace",
		},
		"spec": {
			"selector": {"matchLabels": {"app": "myapp"}},
			"template": {
				"metadata": {"labels": {"app": "myapp"}},
				"spec": {
					"containers": [{
						"name": "container",
						"image": "node:8-alpine",
					}],
					"securityContext": {"seccompProfile": {"type": "Unconfined"}},
				},
			},
		},
	}
	count(r) == 1
}

test_deployment_override_seccomp_profile_unconfined_allowed {
	r := deny with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "mydeployment",
			"namespace": "mynamespace",
		},
		"spec": {
			"selector": {"matchLabels": {"app": "myapp"}},
			"template": {
				"metadata": {"labels": {"app": "myapp"}},
				"spec": {
					"containers": [{
						"name": "container",
						"image": "node:8-alpine",
						"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
					}],
					"securityContext": {"seccompProfile": {"type": "Unconfined"}},
				},
			},
		},
	}
	count(r) == 0
}

test_deployment_override_seccomp_profile_unconfined_deny {
	r := deny with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "mydeployment",
			"namespace": "mynamespace",
		},
		"spec": {
			"selector": {"matchLabels": {"app": "myapp"}},
			"template": {
				"metadata": {"labels": {"app": "myapp"}},
				"spec": {
					"containers": [
						{
							"name": "container",
							"image": "node:8-alpine",
						},
						{
							"name": "container2",
							"image": "node:8-alpine",
							"securityContext": {"seccompProfile": {"type": "Unconfined"}},
						},
					],
					"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
				},
			},
		},
	}
	count(r) == 1
	contains(r[_].msg, "container2")
}

test_cronjob_seccomp_profile_unconfined_denied {
	r := deny with input as {
		"apiVersion": "batch/v1",
		"kind": "CronJob",
		"metadata": {
			"name": "mydeployment",
			"namespace": "mynamespace",
		},
		"spec": {
			"schedule": "* * * * *",
			"jobTemplate": {"spec": {"template": {"spec": {"containers": [{
				"name": "test-container",
				"image": "node:8-alpine",
				"securityContext": {"seccompProfile": {"type": "Unconfined"}},
			}]}}}},
		},
	}
	count(r) == 1
}

test_pod_annotations_seccomp_profile_unconfined_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "mydeployment",
			"annotations": {"container.seccomp.security.alpha.kubernetes.io/test-container": "unconfined"},
		},
		"spec": {"containers": [{
			"name": "test-container",
			"image": "node:8-alpine",
		}]},
	}
	count(r) == 1
}

test_pod_annotations_seccomp_profile_unconfined_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"name": "mydeployment",
			"annotations": {"container.seccomp.security.alpha.kubernetes.io/test-container": "runtime/default"},
		},
		"spec": {"containers": [{
			"name": "test-container",
			"image": "node:8-alpine",
		}]},
	}
	count(r) == 0
}

test_deployment_annotations_seccomp_profile_unconfined_allowed {
	r := deny with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {
			"name": "mydeployment",
			"namespace": "default",
		},
		"spec": {
			"selector": {"matchLabels": {"app": "myapp"}},
			"template": {
				"metadata": {
					"labels": {"app": "myapp"},
					"annotations": {"container.seccomp.security.alpha.kubernetes.io/test-container": "unconfined"},
				},
				"spec": {
					"containers": [{
						"name": "test-container",
						"image": "node:8-alpine",
					}],
					"securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
				},
			},
		},
	}
	count(r) == 0
}
