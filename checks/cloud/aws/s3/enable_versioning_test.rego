package builtin.aws.s3.aws0090_test

import rego.v1

import data.builtin.aws.s3.aws0090 as check
import data.lib.test

test_deny_versioning_disabled if {
	inp := {"aws": {"s3": {"buckets": [{"versioning": {"enabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_versioning_enabled if {
	inp := {"aws": {"s3": {"buckets": [{"versioning": {"enabled": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
