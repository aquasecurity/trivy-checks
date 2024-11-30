package user.kubernetes.no_deployment_allowed_test

import rego.v1

import data.user.kubernetes.no_deployment_allowed as check

test_deny_deployment if {
	inp := {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {"name": "web-app-deployment"},
		"spec": {
			"replicas": 3,
			"selector": {"matchLabels": {"app": "web-app"}},
			"template": {
				"metadata": {"labels": {"app": "web-app"}},
				"spec": {"containers": [{
					"name": "web-app-container",
					"image": "web-app:1.0",
					"ports": [{"containerPort": 80}],
				}]},
			},
		},
	}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_stateful_set if {
	inp := {
		"apiVersion": "apps/v1",
		"kind": "StatefulSet",
		"metadata": {"name": "web-app-statefulset"},
		"spec": {
			"serviceName": "web-app",
			"replicas": 3,
			"selector": {"matchLabels": {"app": "web-app"}},
			"template": {
				"metadata": {"labels": {"app": "web-app"}},
				"spec": {"containers": [{
					"name": "web-app-container",
					"image": "web-app:1.0",
					"ports": [{"containerPort": 80}],
				}]},
			},
		},
	}

	res := check.deny with input as inp
	res == set()
}
