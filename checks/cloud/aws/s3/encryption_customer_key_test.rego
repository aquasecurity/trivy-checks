package builtin.aws.s3.aws0132_test

import rego.v1

import data.builtin.aws.s3.aws0132 as check
import data.lib.test

test_deny_bucket_without_kms_key if {
	inp := {"aws": {"s3": {"buckets": [{"encryption": {}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_bucket_with_kms_key if {
	inp := {"aws": {"s3": {"buckets": [{"encryption": {"kmskeyid": {"value": "test"}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_log_bucket_without_kms_key if {
	inp := {"aws": {"s3": {"buckets": [{
		"encryption": {},
		"acl": {"value": "log-delivery-write"},
	}]}}}
}
