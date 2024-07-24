package builtin.aws.s3.aws0171_test

import rego.v1

import data.builtin.aws.s3.aws0171 as check
import data.lib.test

test_deny_bucket_without_cloudtrail_logging if {
	inp := {"aws": {"s3": {"buckets": [{"name": {"value": "test-bucket"}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_bucket_with_readonly_cloudtrail_logging if {
	inp := build_input("ReadOnly", "AWS::S3::Object", "arn:aws:s3")
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_s3_bucket_with_writeonly_cloudtrail_logging if {
	inp := build_input("WriteOnly", "AWS::S3::Object", "arn:aws:s3")
	res := check.deny with input as inp
	count(res) == 0
}

test_allow_bucket_with_all_cloudtrail_logging if {
	inp := build_input("All", "AWS::S3::Object", "arn:aws:s3")
	res := check.deny with input as inp
	count(res) == 0
}

test_allow_all_cloudtrail_logging_for_this_bucket if {
	inp := build_input("All", "AWS::S3::Object", "arn:aws:s3:::test-bucket/")
	res := check.deny with input as inp
	count(res) == 0
}

test_deny_all_cloudtrail_logging_for_other_bucket if {
	inp := build_input("All", "AWS::S3::Object", "arn:aws:s3:::test-other-bucket/")
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_allall_cloudtrail_logging_for_this_bucket_but_arn_missing_slash if {
	inp := build_input("All", "AWS::S3::Object", "arn:aws:s3::test-bucket")
	res := check.deny with input as inp
	count(res) == 1
}

build_input(readwritetype, datasource_type, arn) := {"aws": {
	"s3": {"buckets": [{"name": {"value": "test-bucket"}}]},
	"cloudtrail": {"trails": [{
		"name": {"value": "test-trail"},
		"eventselectors": [{
			"readwritetype": {"value": readwritetype},
			"dataresources": [{
				"type": {"value": datasource_type},
				"values": [{"value": arn}],
			}],
		}],
	}]},
}}
