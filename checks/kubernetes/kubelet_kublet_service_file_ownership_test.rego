package builtin.kubernetes.KCV0070

import rego.v1

test_validate_service_file_ownership_equal_root_root if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletServiceFileOwnership": {"values": ["root:root"]}},
	}

	count(r) == 0
}

test_validate_service_file_ownership_equal_user if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletServiceFileOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
