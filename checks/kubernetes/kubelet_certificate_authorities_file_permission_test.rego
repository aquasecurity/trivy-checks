package builtin.kubernetes.KCV0075

import rego.v1

test_validate_certificate_authorities_permission_equal_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"certificateAuthoritiesFilePermissions": {"values": [600]}},
	}

	count(r) == 0
}

test_validate_certificate_authorities_permission_lower_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"certificateAuthoritiesFilePermissions": {"values": [500]}},
	}

	count(r) == 0
}

test_validate_certificate_authorities_permission_higher_600 if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"certificateAuthoritiesFilePermissions": {"values": [700]}},
	}

	count(r) == 1
}
