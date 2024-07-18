package builtin.aws.iam.aws0061_test

import rego.v1

import data.builtin.aws.iam.aws0061 as check
import data.lib.test

test_allow_policy_require_uppercase_in_passwords if {
	test.assert_empty(check.deny) with input.aws.iam.passwordpolicy.requireuppercase.value as true
}

test_disallow_policy_no_require_uppercase_in_passwords if {
	inp := {"aws": {"iam": {"passwordpolicy": {"requireuppercase": {"value": false}}}}}
	test.assert_equal_message("Password policy does not require uppercase characters.", check.deny) with input as inp
}
