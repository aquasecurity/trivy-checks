package builtin.aws.mq.aws0071_test

import rego.v1

import data.builtin.aws.mq.aws0071 as check
import data.lib.test

test_allow_with_logging if {
	inp := {"aws": {"mq": {"brokers": [{"logging": {"general": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_without_logging if {
	inp := {"aws": {"mq": {"brokers": [{"logging": {"general": {"value": false}}}]}}}

	test.assert_equal_message("Broker does not have general logging enabled.", check.deny) with input as inp
}
