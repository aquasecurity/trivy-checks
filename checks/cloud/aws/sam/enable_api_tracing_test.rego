package builtin.aws.sam.aws0111_test

import rego.v1

import data.builtin.aws.sam.aws0111 as check
import data.lib.test

test_deny_tracing_disabled if {
	inp := {"aws": {"sam": {"apis": [{"tracingenabled": {"value": false}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_tracing_enabled if {
	inp := {"aws": {"sam": {"apis": [{"tracingenabled": {"value": true}}]}}}

	test.assert_empty(check.deny) with input as inp
}
