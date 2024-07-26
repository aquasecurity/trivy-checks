package builtin.aws.elasticsearch.aws0042_test

import rego.v1

import data.builtin.aws.elasticsearch.aws0042 as check
import data.lib.test

test_allow_logging_enabled if {
	inp := {"aws": {"elasticsearch": {"domains": [{"logpublishing": {"auditenabled": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_disallow_logging_disabled if {
	inp := {"aws": {"elasticsearch": {"domains": [{"logpublishing": {"auditenabled": {"value": false}}}]}}}

	test.assert_equal_message("Domain audit logging is not enabled.", check.deny) with input as inp
}
