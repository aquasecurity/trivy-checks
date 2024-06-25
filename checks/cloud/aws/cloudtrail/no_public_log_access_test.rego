package builtin.aws.cloudtrail.aws0161_test

import rego.v1

import data.builtin.aws.cloudtrail.aws0161 as check
import data.lib.test

test_allow_bucket_without_public_access if {
	inp := {"aws": {
		"cloudtrail": {"trails": [{"bucketname": {"value": "bucket_name"}}]},
		"s3": {"buckets": [{"name": {"value": "bucket_name"}, "acl": {"value": "private"}}]},
	}}
	test.assert_empty(check.deny) with input as inp
}

# TODO: count should be 2
test_disallow_bucket_with_public_access if {
	inp := {"aws": {
		"cloudtrail": {"trails": [{"bucketname": {"value": "bucket_name"}}]},
		"s3": {"buckets": [{"name": {"value": "bucket_name"}, "acl": {"value": "public-read"}}]},
	}}

	test.assert_equal_message("Bucket has public access", check.deny) with input as inp
}
