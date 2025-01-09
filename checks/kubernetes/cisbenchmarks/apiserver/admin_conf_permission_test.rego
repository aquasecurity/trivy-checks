package builtin.kubernetes.KCV0060

import rego.v1

test_validate_admin_config_permission_equal_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"adminConfFilePermissions": {"values": [600]}},
	}

	count(r) == 0
}

test_validate_admin_config_permission_lower_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"adminConfFilePermissions": {"values": [600]}},
	}

	count(r) == 0
}

test_validate_admin_config_permission_higher_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"adminConfFilePermissions": {"values": [700]}},
	}

	count(r) == 1
}
