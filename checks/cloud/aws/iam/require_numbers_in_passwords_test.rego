package builtin.aws.iam.aws0059_test

import rego.v1

import data.builtin.aws.iam.aws0059 as check
import data.lib.test

test_allow_policy_require_numbers_in_passwords if {
	test.assert_empty(check.deny) with input.aws.iam.passwordpolicy.requirenumbers.value as true
}

test_disallow_policy_no_require_numbers_in_passwords if {
	inp := {"aws": {"iam": {"passwordpolicy": {"requirenumbers": {"value": false}}}}}
	test.assert_equal_message("Password policy does not require numbers.", check.deny) with input as inp
}
