package builtin.aws.ec2.aws0164_test

import rego.v1

import data.builtin.aws.ec2.aws0164 as check
import data.lib.test

test_deny_subnet_with_public_ip if {
	inp := {"aws": {"ec2": {"subnets": [{"mappubliciponlaunch": {"value": true}}]}}}

	test.assert_equal_message("Subnet associates public IP address.", check.deny) with input as inp
}

test_allow_subnet_without_public_ip if {
	inp := {"aws": {"ec2": {"subnets": [{"mappubliciponlaunch": {"value": false}}]}}}

	test.assert_empty(check.deny) with input as inp
}
