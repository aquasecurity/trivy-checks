package builtin.aws.ec2.aws0105_test

import rego.v1

import data.builtin.aws.ec2.aws0105 as check
import data.lib.test

test_deny_acl_rule_with_wildcard_address if {
	inp := {"aws": {"ec2": {"networkacls": [{"rules": [{
		"type": {"value": "ingress"},
		"action": {"value": "allow"},
		"cidrs": [{"value": "0.0.0.0/0"}],
	}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_acl_rule_with_specific_address if {
	inp := {"aws": {"ec2": {"networkacls": [{"rules": [{
		"type": {"value": "ingress"},
		"action": {"value": "allow"},
		"cidrs": [{"value": "10.0.0.0/16"}],
	}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
