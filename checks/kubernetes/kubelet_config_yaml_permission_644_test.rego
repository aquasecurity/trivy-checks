package builtin.kubernetes.KCV0095

import rego.v1

test_validate_kubelet_config_yaml_permission_equal_644 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletConfigYamlConfigurationFilePermission": {"values": [644]}},
	}

	count(r) == 0
}

test_validate_kublet_config_yaml_permission_lower_644 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletConfigYamlConfigurationFilePermission": {"values": [500]}},
	}

	count(r) == 0
}

test_validate_kubelet_config_yaml_permission_no_result if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletConfigYamlConfigurationFilePermission": {"values": []}},
	}

	count(r) == 0
}

test_validate_kubelet_config_yaml_permission_higher_644 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletConfigYamlConfigurationFilePermission": {"values": [700]}},
	}

	count(r) == 1
}
