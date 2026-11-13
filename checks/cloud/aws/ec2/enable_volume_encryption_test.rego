package builtin.aws.ec2.aws0026_test

import rego.v1

import data.builtin.aws.ec2.aws0026 as check
import data.lib.test

test_allow_encrypted_volume if {
	inp := build_input({"enabled": {"value": true}})
	test.assert_empty(check.deny) with input as inp
}

test_deny_not_encrypted_volume if {
	inp := build_input({"enabled": {"value": false}})
	test.assert_equal_message("EBS volume is not encrypted.", check.deny) with input as inp
}

test_allow_unresolvable_encryption if {
	inp := build_input({"enabled": {"value": false, "unresolvable": true}})
	test.assert_empty(check.deny) with input as inp
}

test_deny_missing_encryption if {
	inp := {"aws": {"ec2": {"volumes": [{}]}}}
	test.assert_equal_message("EBS volume is not encrypted.", check.deny) with input as inp
}

build_input(encryption) := {"aws": {"ec2": {"volumes": [{"encryption": encryption}]}}}
