package builtin.aws.ec2.aws0131_test

import rego.v1

import data.builtin.aws.ec2.aws0131 as check
import data.lib.test

test_allow_root_block_device_encrypted if {
	inp := {"aws": {"ec2": {"instances": [{"rootblockdevice": {"encrypted": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_root_block_device_not_encrypted if {
	inp := {"aws": {"ec2": {"instances": [{"rootblockdevice": {"encrypted": {"value": false}}}]}}}

	test.assert_equal_message("Instance does not have encryption enabled for root block device", check.deny) with input as inp
}

test_allow_ebs_block_device_encrypted if {
	inp := {"aws": {"ec2": {"instances": [{"ebsblockdevices": [{"encrypted": {"value": true}}]}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_ebs_block_device_not_encrypted if {
	inp := {"aws": {"ec2": {"instances": [{"ebsblockdevices": [{"encrypted": {"value": false}}]}]}}}

	test.assert_equal_message("EBS block device is not encrypted.", check.deny) with input as inp
}
