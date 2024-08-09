package builtin.aws.cloudtrail.aws0016_test

import rego.v1

import data.builtin.aws.cloudtrail.aws0016 as check
import data.lib.test

test_allow_trail_with_log_validation if {
	inp := {"aws": {"cloudtrail": {"trails": [{"enablelogfilevalidation": {"value": true}}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_disallow_trail_without_log_validation if {
	inp := {"aws": {"cloudtrail": {"trails": [{"enablelogfilevalidation": {"value": false}}]}}}
	test.assert_equal_message("Trail does not have log validation enabled.", check.deny) with input as inp
}
