package builtin.aws.iam.aws0165_test

import rego.v1

import data.builtin.aws.iam.aws0165 as check
import data.lib.test

test_disallow_root_user_without_mfa if {
	test.assert_equal_message("Root user does not have a hardware MFA device", check.deny) with input as build_input({"name": {"value": "root"}})
}

test_disallow_root_user_with_virtual_mfa if {
	test.assert_equal_message("Root user does not have a hardware MFA device", check.deny) with input as build_input({
		"name": {"value": "root"},
		"mfadevices": [{"isvirtual": {"value": true}}],
	})
}

test_allow_non_root_user_without_mfa if {
	test.assert_empty(check.deny) with input as build_input({"name": {"value": "other"}})
}

test_allow_root_user_with_hardware_mfa if {
	test.assert_empty(check.deny) with input as build_input({
		"name": {"value": {"value": "root"}},
		"mfadevices": [{"isvirtual": {"value": false}}],
	})
}

test_allow_root_user_with_different_mfa if {
	test.assert_empty(check.deny) with input as build_input({
		"name": {"value": "root"},
		"mfadevices": [
			{"isvirtual": {"value": true}},
			{"isvirtual": {"value": false}},
		],
	})
}

test_allow_without_user if {
	test.assert_empty(check.deny) with input as build_input({})
}

build_input(body) = {"aws": {"iam": {"users": [body]}}}
