package builtin.kubernetes.KCV0069

import rego.v1

test_validate_service_file_permission_equal_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletServiceFilePermissions": {"values": [600]}},
	}

	count(r) == 0
}

test_validate_service_file_permission_lower_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletServiceFilePermissions": {"values": [500]}},
	}

	count(r) == 0
}

test_validate_service_file_permission_higher_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletServiceFilePermissions": {"values": [700]}},
	}

	count(r) == 1
}
