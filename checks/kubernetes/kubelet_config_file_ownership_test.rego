package builtin.kubernetes.KCV0074

import rego.v1

test_validate_kubelet_config_ownership_equal_root_root if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletConfFileOwnership": {"values": ["root:root"]}},
	}

	count(r) == 0
}

test_validate_kubelet_config_ownership_no_results if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletConfFileOwnership": {"values": []}},
	}

	count(r) == 0
}

test_validate_kubelet_config_ownership_equal_user if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletConfFileOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
