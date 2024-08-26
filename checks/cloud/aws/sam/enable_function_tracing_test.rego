package builtin.aws.sam.aws0125_test

import rego.v1

import data.builtin.aws.sam.aws0125 as check
import data.lib.test

test_deny_pass_through_tracing_mode if {
	inp := {"aws": {"sam": {"functions": [{"tracing": {"value": "PassThrough"}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_active_tracing_mode if {
	inp := {"aws": {"sam": {"functions": [{"tracing": {"value": check.tracing_mode_active}}]}}}

	test.assert_empty(check.deny) with input as inp
}
