package builtin.aws.rds.aws0077_test

import rego.v1

import data.builtin.aws.rds.aws0077 as check
import data.lib.test

test_deny_1_retention_period if {
	inp := {"aws": {"rds": {"clusters": [{"backupretentionperioddays": {"value": 1}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_2_retention_period if {
	inp := {"aws": {"rds": {"instances": [{"backupretentionperioddays": {"value": 2}}]}}}

	test.assert_empty(check.deny) with input as inp
}
