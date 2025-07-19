package builtin.kubernetes.KCV0072

import rego.v1

test_validate_kube_config_ownership_equal_root_root if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeconfigFileExistsOwnership": {"values": ["root:root"]}},
	}

	count(r) == 0
}

test_validate_kube_config_ownership_no_results if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeconfigFileExistsOwnership": {"values": []}},
	}

	count(r) == 0
}

test_validate_kube_config_ownership_equal_user if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeconfigFileExistsOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
