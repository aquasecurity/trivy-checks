package builtin.aws.cloudfront.aws0011_test

import rego.v1

import data.builtin.aws.cloudfront.aws0011 as check
import data.lib.test

test_allow_distribution_with_waf if {
	test.assert_empty(check.deny) with input as {"aws": {"cloudfront": {"distributions": [{"wafid": {"value": "test"}}]}}}
}

test_deny_distribution_without_waf if {
	test.assert_equal_message("Distribution does not utilize a WAF.", check.deny) with input as {"aws": {"cloudfront": {"distributions": [{"wafid": {"value": ""}}]}}}
}
