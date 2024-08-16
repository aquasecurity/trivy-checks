package builtin.aws.s3.aws0170_test

import rego.v1

import data.builtin.aws.s3.aws0170 as check
import data.lib.test

test_deny_bucket_without_mfa_delete if {
	inp := {"aws": {"s3": {"buckets": [{"versioning": {"mfadelete": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_bucket_with_mfa_delete if {
	inp := {"aws": {"s3": {"buckets": [{"versioning": {"mfadelete": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
