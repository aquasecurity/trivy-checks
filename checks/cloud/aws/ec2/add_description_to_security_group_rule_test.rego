package builtin.aws.ec2.aws0124_test

import rego.v1

import data.builtin.aws.ec2.aws0124 as check
import data.lib.test

test_allow_rule_with_description if {
	inp := {"aws": {"ec2": {"securitygroups": [{"egressrules": [{"description": {"value": "test"}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_disallow_rule_without_description if {
	inp := {"aws": {"ec2": {"securitygroups": [{"egressrules": [{"description": {"value": ""}}]}]}}}

	test.assert_equal_message("Security group rule does not have a description.", check.deny) with input as inp
}
