package builtin.aws.ec2.aws0178_test

import rego.v1

import data.builtin.aws.ec2.aws0178 as check
import data.lib.test

test_allow_vpc_with_flow_logs if {
	inp := {"aws": {"ec2": {"vpcs": [{"flowlogsenabled": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_vpc_without_flow_logs if {
	inp := {"aws": {"ec2": {"vpcs": [{"flowlogsenabled": {"value": false}}]}}}

	test.assert_equal_message("VPC does not have VPC Flow Logs enabled.", check.deny) with input as inp
}
