package builtin.aws.dynamodb.aws0024_test

import rego.v1

import data.builtin.aws.dynamodb.aws0024 as check
import data.lib.test

test_allow_cluster_with_recovery if {
	inp := {"aws": {"dynamodb": {"tables": [{"pointintimerecovery": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_cluster_without_recovery if {
	inp := {"aws": {"dynamodb": {"tables": [{"pointintimerecovery": {"value": false}}]}}}

	test.assert_equal_message("Point-in-time recovery is not enabled.", check.deny) with input as inp
}

test_allow_table_with_recovery if {
	inp := {"aws": {"dynamodb": {"tables": [{"pointintimerecovery": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_table_without_recovery if {
	inp := {"aws": {"dynamodb": {"tables": [{"pointintimerecovery": {"value": false}}]}}}

	test.assert_equal_message("Point-in-time recovery is not enabled.", check.deny) with input as inp
}
