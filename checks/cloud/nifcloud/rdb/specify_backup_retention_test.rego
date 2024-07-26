package builtin.nifcloud.rdb.nifcloud0009_test

import rego.v1

import data.builtin.nifcloud.rdb.nifcloud0009 as check
import data.lib.test

test_allow_frequent_retention_perid if {
	inp := {"nifcloud": {"rdb": {"dbinstances": {{"backupretentionperioddays": {"value": 5}}}}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_low_retention_period if {
	inp := {"nifcloud": {"rdb": {"dbinstances": {{"backupretentionperioddays": {"value": 1}}}}}}

	res := check.deny with input as inp
	count(res) == 1
}
