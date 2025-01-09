package builtin.kubernetes.KCV0059

import rego.v1

test_validate_data_directory_ownership_equal_root_root if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"etcdDataDirectoryOwnership": {"values": ["etcd:etcd"]}},
	}

	count(r) == 0
}

test_validate_data_directory_ownership_equal_user if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"etcdDataDirectoryOwnership": {"values": ["user:user"]}},
	}

	count(r) == 1
}
