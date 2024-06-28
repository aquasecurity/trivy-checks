package builtin.aws.iam.aws0142_test

import rego.v1

import data.builtin.aws.iam.aws0142 as check
import data.lib.test

test_disallow_root_user_without_mfa if {
	test.assert_equal_message("Root user does not have an MFA device", check.deny) with input as build_input({"name": {"value": "root"}})
}

test_allow_non_root_user_without_mfa if {
	test.assert_empty(check.deny) with input as build_input({"name": {"value": "other"}})
}

test_allow_root_user_with_mfa if {
	test.assert_empty(check.deny) with input as build_input({
		"name": "root",
		"mfadevices": [
			{"isvirtual": {"value": false}},
			{"isvirtual": {"value": true}},
		],
	})
}

build_input(body) = {"aws": {"iam": {"users": [body]}}}
