package builtin.aws.cloudtrail.aws0163_test

import rego.v1

import data.builtin.aws.cloudtrail.aws0163 as check
import data.lib.test

test_allow_bucket_with_logging_enabled if {
	inp := {"aws": {
		"cloudtrail": {"trails": [{"bucketname": {"value": "bucket1"}}]},
		"s3": {"buckets": [{
			"name": {"value": "bucket1"},
			"logging": {"enabled": {"value": true}},
		}]},
	}}

	test.assert_empty(check.deny) with input as inp
}

test_disallow_bucket_with_logging_disabled if {
	inp := {"aws": {
		"cloudtrail": {"trails": [{"bucketname": {"value": "bucket1"}}]},
		"s3": {"buckets": [{
			"name": {"value": "bucket1"},
			"logging": {"enabled": {"value": false}},
		}]},
	}}

	test.assert_equal_message(
		"Trail S3 bucket does not have logging enabled",
		check.deny,
	) with input as inp
}
