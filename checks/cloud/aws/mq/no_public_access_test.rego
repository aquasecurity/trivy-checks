package builtin.aws.mq.aws0072_test

import rego.v1

import data.builtin.aws.mq.aws0072 as check
import data.lib.test

test_allow_without_public_access if {
	inp := {"aws": {"mq": {"brokers": [{"publicaccess": {"value": false}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_with_public_access if {
	inp := {"aws": {"mq": {"brokers": [{"publicaccess": {"value": true}}]}}}

	test.assert_equal_message("Broker has public access enabled.", check.deny) with input as inp
}
