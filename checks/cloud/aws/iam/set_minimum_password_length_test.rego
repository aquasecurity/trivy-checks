package builtin.aws.iam.aws0063_test

import rego.v1

import data.builtin.aws.iam.aws0063 as check
import data.lib.test

test_allow_password_length_over_14 if {
	inp := {"aws": {"iam": {"passwordpolicy": {"minimumlength": {"value": 15}}}}}
	test.assert_empty(check.deny) with input as inp
}

test_disallow_password_length_under_14 if {
	inp := {"aws": {"iam": {"passwordpolicy": {"minimumlength": {"value": 13}}}}}
	test.assert_equal_message("Password policy allows a maximum password age of greater than 90 days", check.deny) with input as inp
}
