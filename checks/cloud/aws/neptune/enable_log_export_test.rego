package builtin.aws.neptune.aws0075_test

import rego.v1

import data.builtin.aws.neptune.aws0075 as check
import data.lib.test

test_deny_audit_logging_disabled if {
	inp := {"aws": {"neptune": {"clusters": [{"logging": {"audit": {"value": false}}}]}}}

	test.assert_count(check.deny, 1) with input as inp
}

test_allow_logging_enabled if {
	inp := {"aws": {"neptune": {"clusters": [{"logging": {"audit": {"value": true}}}]}}}

	test.assert_empty(check.deny) with input as inp
}
