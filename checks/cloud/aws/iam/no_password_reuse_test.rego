package builtin.aws.iam.aws0056_test

import rego.v1

import data.builtin.aws.iam.aws0056 as check
import data.lib.test

test_disallow_policy_with_less_than_5_password_reuse if {
	inp = {"aws": {"iam": {"passwordpolicy": {"reusepreventioncount": {"value": 1}}}}}
	test.assert_equal_message("Password policy allows reuse of recent passwords.", check.deny) with input as inp
}

test_allow_policy_with_5_password_reuse if {
	test.assert_empty(check.deny) with input as {"aws": {"iam": {"passwordpolicy": {"reusepreventioncount": {"value": 5}}}}}
}
