package builtin.aws.iam.aws0141_test

import rego.v1

import data.builtin.aws.iam.aws0141 as check
import data.lib.test

test_allow_root_user_without_access_keys if {
	test.assert_empty(check.deny) with input as build_input({"name": {"value": "root"}})
}

test_allow_non_root_user_without_access_keys if {
	test.assert_empty(check.deny) with input as build_input({"name": {"value": "user"}})
}

test_allow_non_root_user_with_access_keys if {
	test.assert_empty(check.deny) with input as build_input({
		"name": {"value": "user"},
		"accesskeys": [{"active": {"value": true}}],
	})
}

test_allow_root_user_with_inactive_access_keys if {
	test.assert_empty(check.deny) with input as build_input({
		"name": {"value": "root"},
		"accesskeys": [{"active": {"value": false}}],
	})
}

test_disallow_root_user_with_active_access_keys if {
	test.assert_equal_message("Access key exists for root user", check.deny) with input as build_input({
		"name": {"value": "root"},
		"accesskeys": [
			{"active": {"value": false}},
			{"active": {"value": true}},
		],
	})
}

build_input(body) := {"aws": {"iam": {"users": [body]}}}
