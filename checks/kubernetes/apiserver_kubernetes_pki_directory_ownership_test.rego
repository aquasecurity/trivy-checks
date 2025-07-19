package builtin.kubernetes.KCV0066

import rego.v1

test_validate_pki_directory_ownership_equal_root_root if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubePKIDirectoryFileOwnership": {"values": ["root:root"]}},
	}

	count(r) == 0
}

test_validate_pki_directory_ownership_equal_user if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubePKIDirectoryFileOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
