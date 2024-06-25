package builtin.aws.cloudtrail.aws0162_test

import rego.v1

import data.builtin.aws.cloudtrail.aws0162 as check
import data.lib.test

test_allow_cloudwatch_integration if {
	inp := {"aws": {"cloudtrail": {"trails": [{"cloudwatchlogsloggrouparn": {"value": "log-group-arn"}}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_disallow_without_cloudwatch_integration if {
	inp := {"aws": {"cloudtrail": {"trails": [{"cloudwatchlogsloggrouparn": {"value": ""}}]}}}
	test.assert_equal_message("CloudWatch integration is not configured.", check.deny) with input as inp
}
