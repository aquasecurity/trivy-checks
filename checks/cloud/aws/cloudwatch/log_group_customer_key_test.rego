package builtin.aws.cloudwatch.aws0017_test

import rego.v1

import data.builtin.aws.cloudwatch.aws0017 as check
import data.lib.test

test_allow_log_group_with_cmk if {
	inp := {"aws": {"cloudwatch": {"loggroups": [{"kmskeyid": {"value": "some-key-id"}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_log_group_without_cmk if {
	inp := {"aws": {"cloudwatch": {"loggroups": [{"kmskeyid": {"value": ""}}]}}}

	test.assert_equal_message("Log group is not encrypted.", check.deny) with input as inp
}
