package builtin.kubernetes.KCV0090

import rego.v1

test_validate_rotate_certificates_true if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletRotateCertificatesArgumentSet": {"values": ["true"]}},
	}

	count(r) == 0
}

test_validate_rotate_certificates_false if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletRotateCertificatesArgumentSet": {"values": ["false"]}},
	}

	count(r) == 1
}

test_validate_rotate_certificates_empty if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletRotateCertificatesArgumentSet": {"values": []}},
	}

	count(r) == 1
}
