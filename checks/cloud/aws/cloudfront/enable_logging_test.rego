package builtin.aws.cloudfront.aws0010_test

import rego.v1

import data.builtin.aws.cloudfront.aws0010 as check
import data.lib.test

test_allow_distribution_with_logging if {
	inp := {"aws": {"cloudfront": {"distributions": [{"logging": {"bucket": {"value": "somebucket"}}}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_allow_distribution_with_v2_logging if {
	inp := {"aws": {"cloudfront": {"distributions": [{"logging": {"bucket": {"value": ""}, "v2": {"enabled": {"value": true}}}}]}}}
	test.assert_empty(check.deny) with input as inp
}

test_deny_distribution_without_logging if {
	inp := {"aws": {"cloudfront": {"distributions": [{"logging": {"bucket": {"value": ""}, "v2": {"enabled": {"value": false}}}}]}}}
	test.assert_count(check.deny, 1) with input as inp
}

test_deny_distribution_entirely_missings_logging if {
	inp := {"aws": {"cloudfront": {"distributions": [{}]}}}
	test.assert_count(check.deny, 1) with input as inp
}
