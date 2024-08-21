package builtin.aws.ec2.aws0008_test

import rego.v1

import data.builtin.aws.ec2.aws0008 as check
import data.lib.test

test_allow_root_block_device_encrypted if {
	inp := {"aws": {"ec2": {"launchconfigurations": [{"rootblockdevice": {"encrypted": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_ebs_block_device_encrypted if {
	inp := {"aws": {"ec2": {"launchconfigurations": [{"ebsblockdevices": [{"encrypted": {"value": true}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_root_block_device_not_encrypted if {
	inp := {"aws": {"ec2": {"launchconfigurations": [{"rootblockdevice": {"encrypted": {"value": false}}}]}}}

	test.assert_equal_message("Root block device is not encrypted.", check.deny) with input as inp
}

test_deny_ebs_block_device_not_encrypted if {
	inp := {"aws": {"ec2": {"launchconfigurations": [{"ebsblockdevices": [{"encrypted": {"value": false}}]}]}}}

	test.assert_equal_message("EBS block device is not encrypted.", check.deny) with input as inp
}
