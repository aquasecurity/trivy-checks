package builtin.aws.neptune.aws0076_test

import rego.v1

import data.builtin.aws.neptune.aws0076 as check
import data.lib.test

test_deny_storage_not_encrypted if {
	inp := {"aws": {"neptune": {"clusters": [{"storageencrypted": {"value": false}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_storage_encrypted if {
	inp := {"aws": {"neptune": {"clusters": [{"storageencrypted": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}
