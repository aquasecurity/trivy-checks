package builtin.kubernetes.KCV0089

import rego.v1

test_validate_tls_key_file_empty if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletTlsPrivateKeyFileArgumentSet": {"values": []}},
	}

	count(r) == 1
}

test_validate_tls_key_file_real if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletTlsPrivateKeyFileArgumentSet": {"values": ["a.key"]}},
	}

	count(r) == 0
}

test_validate_tls_key_file_fake if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletTlsPrivateKeyFileArgumentSet": {"values": ["a.txt"]}},
	}

	count(r) == 1
}
