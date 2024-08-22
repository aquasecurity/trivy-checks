package builtin.aws.iam.aws0140_test

import rego.v1

import data.builtin.aws.iam.aws0140 as check
import data.lib.datetime
import data.lib.test

test_allow_root_user_never_logged_in if {
	test.assert_empty(check.deny) with input as build_input({
		"name": {"value": "root"},
		"lastaccess": {"value": datetime.zero_time_string},
	})
}

test_allow_root_user_logged_in_over_24_hours if {
	test.assert_empty(check.deny) with input as build_input({
		"name": {"value": "root"},
		"lastaccess": {"value": time.format(time.now_ns() - datetime.days_to_ns(7))},
	})
}

test_disallow_root_user_logged_in_within_24_hours if {
	test.assert_equal_message("The root user logged in within the last 24 hours", check.deny) with input as build_input({
		"name": {"value": "root"},
		"lastaccess": {"value": time.format(time.now_ns())},
	})
}

test_allow_nonroot_user_logged_in_within_24_hours if {
	test.assert_empty(check.deny) with input as build_input({
		"name": {"value": "other"},
		"lastaccess": {"value": time.format(time.now_ns())},
	})
}

build_input(body) = {"aws": {"iam": {"users": [body]}}}
