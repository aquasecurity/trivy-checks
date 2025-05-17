package builtin.kubernetes.KCV0079

import rego.v1

test_validate_kubelet_anonymous_auth_set_true if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletAnonymousAuthArgumentSet": {"values": ["true"]}},
	}

	count(r) == 1
}

test_validate_kubelet_anonymous_auth_not_set if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletAnonymousAuthArgumentSet": {"values": []}},
	}

	count(r) == 0
}

test_validate_kubelet_anonymous_auth_set_false if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletAnonymousAuthArgumentSet": {"values": ["false"]}},
	}

	count(r) == 0
}
