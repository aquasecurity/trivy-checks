package builtin.aws.ec2.aws0101_test

import rego.v1

import data.builtin.aws.ec2.aws0101 as check
import data.lib.test

test_allow_no_default_vpc if {
	inp := build_input({"isdefault": {"value": false}})

	test.assert_empty(check.deny) with input as inp
}

test_deny_default_vpc if {
	inp := build_input({"isdefault": {"value": true}})

	test.assert_equal_message("Default VPC is used.", check.deny) with input as inp
}

build_input(vpc) := {"aws": {"ec2": {"vpcs": [vpc]}}}
