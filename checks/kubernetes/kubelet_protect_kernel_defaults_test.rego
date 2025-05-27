package builtin.kubernetes.KCV0083

import rego.v1

test_validate_kernel_defaults_auth_set_true if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletProtectKernelDefaultsArgumentSet": {"values": ["false"]}},
	}

	count(r) == 1
}

test_validate_kubelet_defaults_auth_set if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletProtectKernelDefaultsArgumentSet": {"values": []}},
	}

	count(r) == 1
}

test_validate_kubelet_defaults_auth_set_false if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletProtectKernelDefaultsArgumentSet": {"values": ["true"]}},
	}

	count(r) == 0
}
