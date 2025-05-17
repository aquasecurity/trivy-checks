package builtin.kubernetes.KCV0065

import rego.v1

test_validate_controller_manager_config_ownership_equal_root_root if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"controllerManagerConfFileOwnership": {"values": ["root:root"]}},
	}

	count(r) == 0
}

test_validate_controller_manager_config_ownership_equal_user if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"controllerManagerConfFileOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
