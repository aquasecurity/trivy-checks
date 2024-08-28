package builtin.aws.rds.aws0078_test

import rego.v1

import data.builtin.aws.rds.aws0078 as check
import data.lib.test

test_allow_perfomance_insights_disabled if {
	inp := {"aws": {"rds": {"instances": [{"performanceinsights": {"enabled": {"value": false}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_perfomance_insights_enabled_but_kms_key_id_missing if {
	inp := {"aws": {"rds": {"instances": [{"performanceinsights": {"enabled": {"value": true}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_perfomance_insights_enabled_with_kms_key_id if {
	inp := {"aws": {"rds": {"instances": [{"performanceinsights": {
		"enabled": {"value": true},
		"kmskeyid": {"value": "foo"},
	}}]}}}

	test.assert_empty(check.deny) with input as inp
}
