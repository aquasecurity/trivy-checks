package builtin.kubernetes.KCV0050

import rego.v1

test_validate_spec_permission_equal_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeControllerManagerSpecFilePermission": {"values": [600]}},
	}

	count(r) == 0
}

test_validate_spec_permission_lower_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeControllerManagerSpecFilePermission": {"values": [500]}},
	}

	count(r) == 0
}

test_validate_spec_permission_higher_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeControllerManagerSpecFilePermission": {"values": [700]}},
	}

	count(r) == 1
}
