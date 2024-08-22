package builtin.aws.s3.aws0086_test

import rego.v1

import data.builtin.aws.s3.aws0086 as check
import data.lib.test

test_deny_public_access_block_missing if {
	inp := {"aws": {"s3": {"buckets": [{}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_public_access_block_does_not_block_public_acls if {
	inp := {"aws": {"s3": {"buckets": [{"publicaccessblock": {"blockpublicacls": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_public_access_block_blocks_public_acls if {
	inp := {"aws": {"s3": {"buckets": [{"publicaccessblock": {"blockpublicacls": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
