package builtin.google.iam.google0011_test

import rego.v1

import data.builtin.google.iam.google0011 as check
import data.lib.google.iam
import data.lib.test

test_deny_role_is_service_account_user_for_project_member if {
	inp := build_input({"members": [{"role": {"value": iam.service_account_user_role}}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_role_is_service_account_user_for_project_binding if {
	inp := build_input({"bindings": [{"role": {"value": iam.service_account_token_creator_role}}]})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_role_is_non_service_account if {
	inp := build_input({
		"members": [{"role": {"value": "roles/nothingInParticular"}}],
		"bindings": [{"role": {"value": "roles/nothingInParticular"}}],
	})

	res := check.deny with input as inp
	res == set()
}

build_input(project) := {"google": {"iam": {"projects": [project]}}}
