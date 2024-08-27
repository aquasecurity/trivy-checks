package builtin.aws.cloudwatch.aws0157_test

import rego.v1

import data.builtin.aws.cloudwatch.aws0157 as check
import data.lib.test

test_allow_change_alarm if {
	inp := {"aws": {
		"cloudtrail": {"trails": [multiregion_trail]},
		"cloudwatch": {
			"loggroups": [{
				"arn": {"value": log_group_arn},
				"metricfilters": [change_metric_filter],
			}],
			"alarms": [change_alarm],
		},
	}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_filter_does_not_exist if {
	inp := {"aws": {
		"cloudtrail": {"trails": [multiregion_trail]},
		"cloudwatch": {
			"loggroups": [{"arn": {"value": log_group_arn}}],
			"alarms": [change_alarm],
		},
	}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_alarm_does_not_exist if {
	inp := {"aws": {
		"cloudtrail": {"trails": [multiregion_trail]},
		"cloudwatch": {"loggroups": [{
			"arn": {"value": log_group_arn},
			"metricfilters": [change_metric_filter],
		}]},
	}}

	test.assert_count(check.deny, 1) with input as inp
}

multiregion_trail := {
	"ismultiregion": {"value": true},
	"islogging": {"value": true},
	"cloudwatchlogsloggrouparn": {"value": log_group_arn},
}

change_alarm := {
	"alarmname": {"value": "ConsoleLoginFailure"},
	"metricname": {"value": "ConsoleLoginFailure"},
	"metrics": [{"id": {"value": "ConsoleLoginFailure"}}],
}

change_metric_filter := {
	"filterpattern": {"value": check.filter_pattern},
	"filtername": {"value": "ConsoleLoginFailure"},
}

log_group_arn := "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"
