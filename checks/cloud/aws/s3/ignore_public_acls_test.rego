package builtin.aws.s3.aws0091_test

import rego.v1

import data.builtin.aws.s3.aws0091 as check
import data.lib.test

test_deny_public_access_block_missing if {
	inp := {"aws": {"s3": {"buckets": [{}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_public_access_block_does_not_ignore_public_acls if {
	inp := {"aws": {"s3": {"buckets": [{"publicaccessblock": {"ignorepublicacls": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_public_access_block_ignores_public_acls if {
	inp := {"aws": {"s3": {"buckets": [{"publicaccessblock": {"ignorepublicacls": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
