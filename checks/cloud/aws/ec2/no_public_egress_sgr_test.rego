package builtin.aws.ec2.aws0104_test

import rego.v1

import data.builtin.aws.ec2.aws0104 as check
import data.lib.test

test_deny_sg_with_public_egress if {
	inp := {"aws": {"ec2": {"securitygroups": [{"egressrules": [{"cidrs": [{"value": "0.0.0.0/0"}]}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_sg_without_private_egress if {
	inp := {"aws": {"ec2": {"securitygroups": [{"egressrules": [{"cidrs": [{"value": "10.0.0.0/16"}]}]}]}}}

	test.assert_empty(check.deny) with input as inp
}
