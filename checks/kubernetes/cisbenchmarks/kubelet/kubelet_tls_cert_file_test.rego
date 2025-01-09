package builtin.kubernetes.KCV0088

import rego.v1

test_validate_tls_cert_file_empty if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletTlsCertFileTlsArgumentSet": {"values": []}},
	}

	count(r) == 1
}

test_validate_tls_cert_file_real if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletTlsCertFileTlsArgumentSet": {"values": ["a.crt"]}},
	}

	count(r) == 0
}

test_validate_tls_cert_file_fake if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletTlsCertFileTlsArgumentSet": {"values": ["a.txt"]}},
	}

	count(r) == 1
}
