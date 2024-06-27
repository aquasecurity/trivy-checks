package builtin.aws.elasticache.aws0051_test

import rego.v1

import data.builtin.aws.elasticache.aws0051 as check
import data.lib.test

test_allow_encyption_enabled if {
	inp := {"aws": {"elasticache": {"replicationgroups": [{"transitencryptionenabled": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_encyption_disabled if {
	inp := {"aws": {"elasticache": {"replicationgroups": [{"transitencryptionenabled": {"value": false}}]}}}

	test.assert_equal_message("Replication group does not have transit encryption enabled.", check.deny) with input as inp
}
