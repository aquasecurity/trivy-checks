package builtin.aws.rds.aws0080_test

import rego.v1

import data.builtin.aws.rds.aws0080 as check
import data.lib.test

test_deny_unencrypted_storage if {
	inp := {"aws": {"rds": {"instances": [{
		"replciationsourcearn": {"value": ""},
		"encryption": {"encryptstorage": {"value": false}},
	}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_encrypted_storage if {
	inp := {"aws": {"rds": {"instances": [{
		"replciationsourcearn": {"value": ""},
		"encryption": {"encryptstorage": {"value": true}},
	}]}}}

	test.assert_empty(check.deny) with input as inp
}
