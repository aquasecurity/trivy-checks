package builtin.aws.s3.aws0088_test

import rego.v1

import data.builtin.aws.s3.aws0088 as check
import data.lib.test

test_deny_bucket_encryption_disabled if {
	inp := {"aws": {"s3": {"buckets": [{"encryption": {"enabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_bucket_encryption_enabled if {
	inp := {"aws": {"s3": {"buckets": [{"encryption": {"enabled": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
