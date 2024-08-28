package builtin.aws.mq.aws0070_test

import rego.v1

import data.builtin.aws.mq.aws0070 as check
import data.lib.test

test_allow_with_audit_logging if {
	inp := {"aws": {"mq": {"brokers": [{"logging": {"audit": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_without_audit_logging if {
	inp := {"aws": {"mq": {"brokers": [{"logging": {"audit": {"value": false}}}]}}}

	test.assert_equal_message("Broker does not have audit logging enabled.", check.deny) with input as inp
}
