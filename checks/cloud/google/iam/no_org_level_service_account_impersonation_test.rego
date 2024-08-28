package builtin.google.iam.google0009_test

import rego.v1

import data.builtin.google.iam.google0009 as check
import data.lib.google.iam
import data.lib.test

test_deny_service_account_for_org_member if {
	inp := build_input({"members": [{"role": {"value": iam.service_account_user_role}}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_service_account_for_org_binding if {
	inp := build_input({"bindings": [{"role": {"value": iam.service_account_token_creator_role}}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_custom_role if {
	inp := build_input({
		"members": [{"role": {"value": "roles/some-custom-role"}}],
		"bindings": [{"role": {"value": "roles/some-custom-role"}}],
	})

	res := check.deny with input as inp
	res == set()
}

build_input(org) := {"google": {"iam": {"organizations": [org]}}}
