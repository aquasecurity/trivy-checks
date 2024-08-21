package builtin.aws.ec2.aws0102_test

import rego.v1

import data.builtin.aws.ec2.aws0102 as check
import data.lib.test

test_deny_rule_allow_all_protocols if {
	inp := build_input({
		"action": {"value": "allow"},
		"protocol": {"value": "all"},
	})

	test.assert_equal_message("Network ACL rule allows access using ALL ports.", check.deny) with input as inp
}

test_deny_rule_allow_all_protocols_2 if {
	inp := build_input({
		"action": {"value": "allow"},
		"protocol": {"value": "-1"},
	})

	test.assert_equal_message("Network ACL rule allows access using ALL ports.", check.deny) with input as inp
}

test_allow_rule_with_tcp_protocol if {
	inp := build_input({
		"action": {"value": "allow"},
		"protocol": {"value": "tcp"},
	})

	test.assert_empty(check.deny) with input as inp
}

test_allow_deny_rule_with_all_protocols if {
	inp := build_input({
		"action": {"value": "deny"},
		"protocol": {"value": "all"},
	})

	test.assert_empty(check.deny) with input as inp
}

build_input(rule) := {"aws": {"ec2": {"networkacls": [{"rules": [rule]}]}}}
