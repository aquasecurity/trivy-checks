package builtin.nifcloud.rdb.nifcloud0008_test

import rego.v1

import data.builtin.nifcloud.rdb.nifcloud0008 as check
import data.lib.test

test_allow_db_without_public_access if {
	inp := {"nifcloud": {"rdb": {"dbinstances": [{"publicaccess": {"value": false}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_db_with_public_access if {
	inp := {"nifcloud": {"rdb": {"dbinstances": [{"publicaccess": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
