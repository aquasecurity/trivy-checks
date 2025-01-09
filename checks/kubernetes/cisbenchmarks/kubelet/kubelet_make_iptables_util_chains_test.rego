package builtin.kubernetes.KCV0084

import rego.v1

test_validate_iptables_util_chains_set_true if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "master",
		"info": {"kubeletMakeIptablesUtilChainsArgumentSet": {"values": ["false"]}},
	}

	count(r) == 1
}

test_validate_iptables_util_chains_set_false if {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "NodeInfo",
		"type": "worker",
		"info": {"kubeletMakeIptablesUtilChainsArgumentSet": {"values": ["true"]}},
	}

	count(r) == 0
}
