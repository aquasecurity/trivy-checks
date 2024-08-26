package builtin.aws.msk.aws0074_test

import rego.v1

import data.builtin.aws.msk.aws0074 as check
import data.lib.test

test_deny_logging_disabled if {
	inp := {"aws": {"msk": {"clusters": [{"logging": {"broker": {
		"s3": {"enabled": {"value": false}},
		"cloudwatch": {"enabled": {"value": false}},
		"firehose": {"enabled": {"value": false}},
	}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_logging_to_s3 if {
	inp := {"aws": {"msk": {"clusters": [{"logging": {"broker": {"s3": {"enabled": {"value": true}}}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
