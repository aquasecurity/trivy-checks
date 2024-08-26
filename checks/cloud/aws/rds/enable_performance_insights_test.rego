package builtin.aws.rds.aws0133_test

import rego.v1

import data.builtin.aws.rds.aws0133 as check
import data.lib.test

test_deny_perfomance_insights_disabled if {
	inp := {"aws": {"rds": {"clusters": [{"instances": [{"instance": {"performanceinsights": {"enabled": {"value": false}}}}]}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_perfomance_insights_enabled if {
	inp := {"aws": {"rds": {"instances": [{"performanceinsights": {"enabled": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
