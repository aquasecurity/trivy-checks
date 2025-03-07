package builtin.kubernetes.KCV0091

import rego.v1

test_validate_rotate_kubelet_server_certificate_true if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletRotateKubeletServerCertificateArgumentSet": {"values": ["true"]}},
	}

	count(r) == 0
}

test_validate_rotate_kubelet_server_certificate_false if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletRotateKubeletServerCertificateArgumentSet": {"values": ["false"]}},
	}

	count(r) == 1
}

test_validate_rotate_kubelet_server_certificate_empty if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletRotateKubeletServerCertificateArgumentSet": {"values": []}},
	}

	count(r) == 1
}
