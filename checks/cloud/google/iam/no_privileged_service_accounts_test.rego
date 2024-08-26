package builtin.google.iam.google0007_test

import rego.v1

import data.builtin.google.iam.google0007 as check
import data.lib.google.iam
import data.lib.test

service_account := "serviceAccount:${google_service_account.test.email}"

test_deny_service_account_granted_owner_role_for_org_member if {
	inp := {"google": {"iam": {"organizations": [members(iam.owner_role, service_account)]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_service_account_granted_editor_role_for_folder_member if {
	inp := {"google": {"iam": {"folders": [members(iam.editor_role, service_account)]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_no_service_accounts_with_excessive_privileges if {
	inp := {"google": {"iam": {
		"organizations": [object.union(
			members(iam.owner_role, "proper@email.com"),
			bindings("roles/logging.logWriter", service_account),
		)],
		"folders": [object.union(
			members(iam.owner_role, "proper@email.com"),
			bindings("roles/logging.logWriter", service_account),
		)],
		"projects": [object.union(
			members(iam.owner_role, "proper@email.com"),
			bindings("roles/logging.logWriter", service_account),
		)],
	}}}

	res := check.deny with input as inp
	res == set()
}

members(role, member) := {"members": [{
	"role": {"value": role},
	"member": {"value": member},
}]}

bindings(role, member) := {"bindings": [{
	"role": {"value": role},
	"members": [{"value": member}],
}]}
