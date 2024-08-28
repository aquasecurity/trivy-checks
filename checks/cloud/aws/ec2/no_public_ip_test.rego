package builtin.aws.ec2.aws0009_test

import rego.v1

import data.builtin.aws.ec2.aws0009 as check
import data.lib.test

test_allow_without_public_ip if {
	inp := {"aws": {"ec2": {"launchconfigurations": [{"associatepublicip": {"value": false}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_with_public_ip if {
	inp := {"aws": {"ec2": {"launchconfigurations": [{"associatepublicip": {"value": true}}]}}}

	test.assert_equal_message("Launch configuration associates public IP address.", check.deny) with input as inp
}
