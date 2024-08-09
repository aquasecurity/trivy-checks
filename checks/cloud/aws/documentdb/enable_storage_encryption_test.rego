package builtin.aws.documentdb.aws0021_test

import rego.v1

import data.builtin.aws.documentdb.aws0021 as check
import data.lib.test

test_allow_with_encryption if {
	inp := {"aws": {"documentdb": {"clusters": [{"storageencrypted": {"value": true}}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_disallow_without_encryption if {
	inp := {"aws": {"documentdb": {"clusters": [{"storageencrypted": {"value": false}}]}}}

	test.assert_equal_message("Cluster storage does not have encryption enabled.", check) with input as inp
}
