package builtin.aws.lambda.aws0066_test

import rego.v1

import data.builtin.aws.lambda.aws0066 as check
import data.lib.test

test_allow_with_active_tracing_mode if {
	inp := {"aws": {"lambda": {"functions": [{"tracing": {"mode": {"value": "Active"}}}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_deny_without_active_tracing_mode if {
	inp := {"aws": {"lambda": {"functions": [{"tracing": {"mode": {"value": "PassThrough"}}}]}}}

	test.assert_equal_message("Function does not have tracing enabled.", check.deny) with input as inp
}
