package builtin.kubernetes.KCV0061

import rego.v1

test_validate_admin_config_ownership_equal_root_root if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"adminConfFileOwnership": {"values": ["root:root"]}},
	}

	count(r) == 0
}

test_validate_admin_config_ownership_equal_user if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"adminConfFileOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
