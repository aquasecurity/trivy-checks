package builtin.kubernetes.KCV0086

import rego.v1

test_validate_hostname_override_set if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletHostnameOverrideArgumentSet": {"values": ["name"]}},
	}

	count(r) == 1
}

test_validate_hostname_override_not_set if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletHostnameOverrideArgumentSet": {"values": []}},
	}

	count(r) == 0
}
