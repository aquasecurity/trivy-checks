package builtin.kubernetes.KSV116

import rego.v1

test_failRootGroupId if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-gid"},
		"spec": {"securityContext": {
			"runAsGroup": 0,
			"supplementalGroups": [0],
			"fsGroup": 0,
		}},
	}

	count(r) > 0
}

test_failRootGroupId_failed if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-gid"},
		"spec": {"securityContext": {
			"runAsGroup": 1001, # Non-zero value
			"supplementalGroups": [1002], # Non-zero value
			"fsGroup": 1003, # Non-zero value
		}},
	}

	count(r) = 0
}

test_failRootGroupId_irrelevant if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ClusterRole",
		"metadata": {"name": "hello"},
	}

	count(r) = 0
}
