package builtin.nifcloud.computing.nifcloud0005_test

import rego.v1

import data.builtin.nifcloud.computing.nifcloud0005 as check
import data.lib.test

test_allow_instance_with_private_lan if {
	inp := {"nifcloud": {"computing": {"instances": [{"networkinterfaces": [{"networkid": {"value": "net-some-private-lan"}}]}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_instance_with_common_network if {
	inp := {"nifcloud": {"computing": {"instances": [{"networkinterfaces": [{"networkid": {"value": "net-COMMON_PRIVATE"}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
