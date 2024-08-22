package builtin.aws.iam.aws0062_test

import rego.v1

import data.builtin.aws.iam.aws0062 as check
import data.lib.test

test_allow_password_with_max_age_days_over_90 if {
	inp := {"aws": {"iam": {"passwordpolicy": {"maxagedays": {"value": 91}}}}}
	test.assert_equal_message("Password policy allows a maximum password age of greater than 90 days.", check.deny) with input as inp
}

test_disallow_password_with_max_age_days_within_90 if {
	inp := {"aws": {"iam": {"passwordpolicy": {"maxagedays": {"value": 60}}}}}
	test.assert_empty(check.deny) with input as inp
}
