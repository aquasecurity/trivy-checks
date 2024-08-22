package builtin.aws.iam.aws0143_test

import rego.v1

import data.builtin.aws.iam.aws0143 as check
import data.lib.test

test_allow_user_without_attached_policies if {
	inp := {"aws": {"iam": {"users": [{"policies": []}]}}}

	test.assert_empty(check.deny) with input as inp
}

test_disallow_user_with_attached_policies if {
	inp := {"aws": {"iam": {"users": [{"policies": [{"name": {"value": "policy_name"}}]}]}}}

	test.assert_equal_message("One or more policies are attached directly to a user", check.deny) with input as inp
}
