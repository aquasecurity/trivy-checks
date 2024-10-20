package builtin.aws.ec2.aws0027_test

import rego.v1

import data.builtin.aws.ec2.aws0027 as check
import data.lib.test

test_allow_volume_with_cmk if {
	inp := build_input({"kmskeyid": {"value": "test"}})
	test.assert_empty(check.deny) with input as inp
}

test_deny_volume_without_cmk if {
	inp := build_input({"kmskeyid": {"value": ""}})
	test.assert_equal_message("EBS volume does not use a customer-managed KMS key.", check.deny) with input as inp
}

build_input(encryption) := {"aws": {"ec2": {"volumes": [{"encryption": encryption}]}}}
