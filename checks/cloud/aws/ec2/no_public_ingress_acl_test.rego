package builtin.aws.ec2.aws0105_test

import rego.v1

import data.builtin.aws.ec2.aws0105 as check
import data.lib.test

import data.lib.net

test_deny_acl_rule_all_ips_for_ssh_port_and_tcp if {
	inp := build_input({
		"protocol": {"value": "tcp"},
		"type": {"value": "ingress"},
		"action": {"value": "allow"},
		"cidrs": [{"value": "0.0.0.0/0"}],
		"fromport": {"value": net.ssh_port},
		"toport": {"value": net.ssh_port},
	})

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_ingress_sq_all_ips_for_all_ports_and_all_ports if {
	inp := build_input({
		"protocol": {"value": "-1"},
		"type": {"value": "ingress"},
		"action": {"value": "allow"},
		"cidrs": [{"value": "0.0.0.0/0"}],
		"fromport": {"value": 0},
		"toport": {"value": 0},
	})

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_acl_rule_restrictive_cidr_range if {
	inp := build_input({
		"protocol": {"value": "tcp"},
		"type": {"value": "ingress"},
		"action": {"value": "allow"},
		"cidrs": [{"value": "10.0.0.0/16"}],
		"fromport": {"value": net.ssh_port},
		"toport": {"value": net.ssh_port},
	})

	test.assert_empty(check.deny) with input as inp
}

build_input(rule) := {"aws": {"ec2": {"networkacls": [{"rules": [rule]}]}}}
