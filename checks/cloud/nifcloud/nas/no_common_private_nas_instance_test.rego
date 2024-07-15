package builtin.nifcloud.nas.nifcloud0013_test

import rego.v1

import data.builtin.nifcloud.nas.nifcloud0013 as check
import data.lib.test

test_allow_private_lan if {
	inp := {"nifcloud": {"nas": {"nasinstances": [{"networkid": {"value": "net-some-private-lan"}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_common_private_lan if {
	inp := {"nifcloud": {"nas": {"nasinstances": [{"networkid": {"value": "net-COMMON_PRIVATE"}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
