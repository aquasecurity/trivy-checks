package builtin.aws.ec2.aws0099_test

import rego.v1

import data.builtin.aws.ec2.aws0099 as check
import data.lib.test

test_allow_sg_with_description if {
	inp := {"aws": {"ec2": {"securitygroups": [{"description": {"value": "test"}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_disallow_sg_without_description if {
	inp := {"aws": {"ec2": {"securitygroups": [{"description": {"value": ""}}]}}}

	test.assert_equal_message("Security group does not have a description", check.deny) with input as inp
}

test_disallow_sg_with_default_description if {
	inp := {"aws": {"ec2": {"securitygroups": [{"description": {"value": "Managed by Terraform"}}]}}}

	test.assert_equal_message("Security group explicitly uses the default description", check.deny) with input as inp
}
