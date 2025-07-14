package builtin.aws.ec2.aws0344_test

import rego.v1

import data.builtin.aws.ec2.aws0344 as check
import data.lib.test

test_deny_missing_owners if {
	msg := "AWS AMI data source should specify owners to ensure AMIs come from trusted sources"
	test.assert_equal_message(msg, check.deny) with input as {"aws": {"ec2": {"requestedamis": [{}]}}}
}

test_allow_valid_owners if {
	test.assert_empty(check.deny) with input as {"aws": {"ec2": {"requestedamis": [{"owners": [{"value": "self"}]}]}}}
}

test_allow_valid_multiple_owners if {
	test.assert_empty(check.deny) with input as {"aws": {"ec2": {"requestedamis": [{"owners": [{"value": "amazon"}, {"value": "self"}]}]}}}
}
