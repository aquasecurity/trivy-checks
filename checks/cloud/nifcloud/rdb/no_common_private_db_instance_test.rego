package builtin.nifcloud.rdb.nifcloud0010_test

import rego.v1

import data.builtin.nifcloud.rdb.nifcloud0010 as check
import data.lib.test

test_allow_db_with_private_lan if {
	inp := {"nifcloud": {"rdb": {"dbinstances": [{"networkid": {"value": "net-some-private-lan"}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_db_with_common_private_lan if {
	inp := {"nifcloud": {"rdb": {"dbinstances": [{"networkid": {"value": "net-COMMON_PRIVATE"}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
