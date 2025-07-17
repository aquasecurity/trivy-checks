package builtin.kubernetes.KCV0053

import rego.v1

test_validate_spec_ownership_equal_root_root if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeSchedulerSpecFileOwnership": {"values": ["root:root"]}},
	}

	count(r) == 0
}

test_validate_spec_ownership_equal_user if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeSchedulerSpecFileOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
