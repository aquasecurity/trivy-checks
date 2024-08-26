package builtin.aws.rds.aws0079_test

import rego.v1

import data.builtin.aws.rds.aws0079 as check
import data.lib.test

test_deny_encryption_disabled if {
	inp := {"aws": {"rds": {"clusters": [{"encryption": {"encryptstorage": {"value": false}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_kms_key_missing if {
	inp := {"aws": {"rds": {"clusters": [{"encryption": {
		"encryptstorage": {"value": true},
		"kmskeyid": {"value": ""},
	}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_encryption_enabled_and_kms_key_present if {
	inp := {"aws": {"rds": {"clusters": [{"encryption": {
		"encryptstorage": {"value": true},
		"kmskeyid": {"value": "foo"},
	}}]}}}

	test.assert_empty(check.deny) with input as inp
}
