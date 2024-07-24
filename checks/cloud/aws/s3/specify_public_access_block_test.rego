package builtin.aws.s3.aws0094_test

import rego.v1

import data.builtin.aws.s3.aws0094 as check
import data.lib.test

test_deny_public_access_block_missing if {
	inp := {"aws": {"s3": {"buckets": [{}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_public_access_block_present if {
	inp := {"aws": {"s3": {"buckets": [{"publicaccessblock": {"blockpublicacls": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
