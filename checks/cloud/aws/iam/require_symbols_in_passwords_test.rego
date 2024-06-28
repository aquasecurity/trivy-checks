package builtin.aws.iam.aws0060_test

import rego.v1

import data.builtin.aws.iam.aws0060 as check
import data.lib.test

test_allow_policy_require_symbols_in_passwords if {
	inp := {"aws": {"iam": {"passwordpolicy": {"__defsec_metadata": {"managed": true}, "requiresymbols": {"value": true}}}}}
	test.assert_empty(check.deny) with input as inp
}

test_disallow_policy_no_require_symbols_in_passwords if {
	inp := {"aws": {"iam": {"passwordpolicy": {"__defsec_metadata": {"managed": true}, "requiresymbols": {"value": false}}}}}
	test.assert_equal_message("Password policy does not require symbols.", check.deny) with input as inp
}
