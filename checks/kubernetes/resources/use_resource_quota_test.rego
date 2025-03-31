package builtin.kubernetes.KSV040

import rego.v1

test_use_resource_quota_configure if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {"hard": {
			"requests.cpu": "1",
			"requests.memory": "1Gi",
			"limits.cpu": "2",
			"limits.memory": "2Gi",
		}},
	}

	count(r) == 0
}

test_use_resource_quota_configure_no_hard if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {},
	}

	r[_].msg == "A resource quota policy with hard memory and CPU limits should be configured per namespace"
}

test_use_resource_quota_configure_no_request_cpu if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {"hard": {
			"requests.memory": "1Gi",
			"limits.cpu": "2",
			"limits.memory": "2Gi",
		}},
	}

	r[_].msg == "A resource quota policy with hard memory and CPU limits should be configured per namespace"
}

test_use_resource_quota_configure_no_request_memory if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {"hard": {
			"requests.cpu": "1",
			"limits.cpu": "2",
			"limits.memory": "2Gi",
		}},
	}

	r[_].msg == "A resource quota policy with hard memory and CPU limits should be configured per namespace"
}

test_use_resource_quota_configure_no_limits_cpu if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {"hard": {
			"requests.cpu": "1",
			"requests.memory": "1Gi",
			"limits.memory": "2Gi",
		}},
	}

	r[_].msg == "A resource quota policy with hard memory and CPU limits should be configured per namespace"
}

test_use_resource_quota_configure_no_limits_memory if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {"hard": {
			"requests.cpu": "1",
			"requests.memory": "1Gi",
			"limits.cpu": "2",
		}},
	}

	r[_].msg == "A resource quota policy with hard memory and CPU limits should be configured per namespace"
}
