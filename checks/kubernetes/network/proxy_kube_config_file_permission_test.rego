package builtin.kubernetes.KCV0071

import rego.v1

test_validate_kube_config_permission_equal_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeconfigFileExistsPermissions": {"values": [600]}},
	}

	count(r) == 0
}

test_validate_kube_config_permission_lower_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeconfigFileExistsPermissions": {"values": [500]}},
	}

	count(r) == 0
}

test_validate_kube_config_permission_no_result if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeconfigFileExistsPermissions": {"values": []}},
	}

	count(r) == 0
}

test_validate_kube_config_permission_higher_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeconfigFileExistsPermissions": {"values": [700]}},
	}

	count(r) == 1
}
