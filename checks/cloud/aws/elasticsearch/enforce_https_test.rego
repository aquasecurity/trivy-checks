package builtin.aws.elasticsearch.aws0046_test

import rego.v1

import data.builtin.aws.elasticsearch.aws0046 as check
import data.lib.test

test_allow_enforce_https if {
	inp := {"aws": {"elasticsearch": {"domains": [{"endpoint": {"enforcehttps": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_does_not_enforce_https if {
	inp := {"aws": {"elasticsearch": {"domains": [{"endpoint": {"enforcehttps": {"value": false}}}]}}}

	test.assert_equal_message("Domain does not enforce HTTPS.", check.deny) with input as inp
}
