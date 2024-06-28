package builtin.aws.iam.aws0145_test

import rego.v1

import data.builtin.aws.iam.aws0145 as check
import data.lib.datetime
import data.lib.test

test_disallow_user_logged_in_without_mfa if {
	test.assert_equal_message("User account does not have MFA", check.deny) with input as build_input({
		"name": {"value": "other"},
		"lastaccess": {"value": time.format(time.now_ns())},
	})
}

test_allow_user_never_logged_in_with_mfa if {
	test.assert_empty(check.deny) with input as build_input({
		"name": {"value": "other"},
		"lastaccess": {"value": datetime.zero_time_string},
	})
}

test_allow_user_logged_in_with_mfa if {
	test.assert_empty(check.deny) with input as build_input({
		"name": {"value": "other"},
		"lastaccess": {"value": time.format(time.now_ns())},
		"mfadevices": [{"isvirtual": {"value": false}}],
	})
}

build_input(body) = {"aws": {"iam": {"users": [body]}}}
