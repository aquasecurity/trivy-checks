package builtin.kubernetes.KCV0087

import rego.v1

test_validate_event_qps_bigger_zero if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletEventQpsArgumentSet": {"values": [5]}},
	}

	count(r) == 0
}

test_validate_event_qps_equal_zero if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletEventQpsArgumentSet": {"values": [0]}},
	}

	count(r) == 0
}

test_validate_event_qps_lower_zero if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletEventQpsArgumentSet": {"values": [-1]}},
	}

	count(r) == 1
}
