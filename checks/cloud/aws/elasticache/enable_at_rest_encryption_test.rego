package builtin.aws.elasticache.aws0045_test

import rego.v1

import data.builtin.aws.elasticache.aws0045 as check
import data.lib.test

test_allow_with_encryption_enabled if {
	inp := {"aws": {"elasticache": {"replicationgroups": [{"atrestencryptionenabled": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_with_encryption_disabled if {
	inp := {"aws": {"elasticache": {"replicationgroups": [{"atrestencryptionenabled": {"value": false}}]}}}

	test.assert_equal_message("Replication group does not have at-rest encryption enabled.", check.deny) with input as inp
}
