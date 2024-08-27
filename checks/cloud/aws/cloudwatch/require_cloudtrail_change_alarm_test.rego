package builtin.aws.cloudwatch.aws0151_test

import rego.v1

import data.builtin.aws.cloudwatch.aws0151 as check
import data.lib.test

test_allow_trail_alarms_on_configuration_change if {
	inp := {"aws": {
		"cloudtrail": {"trails": [{
			"ismultiregion": {"value": true},
			"islogging": {"value": true},
			"cloudwatchlogsloggrouparn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"},
		}]},
		"cloudwatch": {
			"loggroups": [{
				"arn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"},
				"metricfilters": [{
					"filterpattern": {"value": "{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}"},
					"filtername": {"value": "CloudTrailConfigurationChange"},
				}],
			}],
			"alarms": [{
				"alarmname": {"value": "CloudTrailConfigurationChange"},
				"metricname": {"value": "CloudTrailConfigurationChange"},
				"metrics": [{"id": {"value": "CloudTrailConfigurationChange"}}],
			}],
		},
	}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_trail_does_not_have_filter_for_configuration_change if {
	inp := {"aws": {
		"cloudtrail": {"trails": [{
			"ismultiregion": {"value": true},
			"islogging": {"value": true},
			"cloudwatchlogsloggrouparn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"},
		}]},
		"cloudwatch": {
			"loggroups": [{"arn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"}}],
			"alarms": [{"alarmname": {"value": "OtherAlarm"}}],
		},
	}}

	test.assert_count(check.deny, 1) with input as inp
}

test_deny_trail_does_not_have_alarm_for_configuration_change if {
	inp := {"aws": {
		"cloudtrail": {"trails": [{
			"ismultiregion": {"value": true},
			"islogging": {"value": true},
			"cloudwatchlogsloggrouparn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"},
		}]},
		"cloudwatch": {
			"loggroups": [{
				"arn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"},
				"metricfilters": [{
					"filterpattern": {"value": "{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}"},
					"filtername": {"value": "CloudTrailConfigurationChange"},
				}],
			}],
			"alarms": [{"metricname": {"value": "OtherAlarm"}}],
		},
	}}

	test.assert_equal_message("Cloudtrail has no IAM Policy change alarm", check.deny) with input as inp
}

test_allow_trail_is_not_multiregion if {
	inp := {"aws": {
		"cloudtrail": {"trails": [{
			"ismultiregion": {"value": false},
			"islogging": {"value": true},
			"cloudwatchlogsloggrouparn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"},
		}]},
		"cloudwatch": {
			"loggroups": [{"arn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"}}],
			"alarms": [],
		},
	}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_trail_is_not_logging if {
	inp := {"aws": {
		"cloudtrail": {"trails": [{
			"ismultiregion": {"value": true},
			"islogging": {"value": false},
			"cloudwatchlogsloggrouparn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"},
		}]},
		"cloudwatch": {
			"loggroups": [{"arn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"}}],
			"alarms": [],
		},
	}}

	test.assert_empty(check.deny) with input as inp
}

test_allow_trail_without_loggroup if {
	inp := {"aws": {
		"cloudtrail": {"trails": [{
			"ismultiregion": {"value": true},
			"islogging": {"value": true},
		}]},
		"cloudwatch": {
			"loggroups": [{"arn": {"value": "arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging"}}],
			"alarms": [],
		},
	}}

	test.assert_empty(check.deny) with input as inp
}
