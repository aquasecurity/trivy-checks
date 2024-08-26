package builtin.aws.sam.aws0121_test

import rego.v1

import data.builtin.aws.sam.aws0121 as check
import data.lib.test

test_deny_table_sse_disabled if {
	inp := {"aws": {"sam": {"simpletables": [{"ssespecification": {"enabled": {"value": false}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_table_sse_enabled if {
	inp := {"aws": {"sam": {"simpletables": [{"ssespecification": {"enabled": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
