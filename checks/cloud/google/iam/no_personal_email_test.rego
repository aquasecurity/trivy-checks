package builtin.google.iam.google0069_test

import rego.v1

import data.builtin.google.iam.google0069 as check

test_deny_binding_with_gmail_user if {
	inp := build_input_bindings([{
		"role": {"value": "roles/viewer"},
		"members": [{"value": "user:john.doe@gmail.com"}],
	}])

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_binding_with_yahoo_user if {
	inp := build_input_bindings([{
		"role": {"value": "roles/editor"},
		"members": [{"value": "user:jane.smith@yahoo.com"}],
	}])

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_binding_with_hotmail_user if {
	inp := build_input_bindings([{
		"role": {"value": "roles/owner"},
		"members": [{"value": "user:test.user@hotmail.com"}],
	}])

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_member_with_gmail_user if {
	inp := build_input_members([{
		"role": {"value": "roles/viewer"},
		"member": {"value": "user:admin@gmail.com"},
	}])

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_member_with_outlook_user if {
	inp := build_input_members([{
		"role": {"value": "roles/editor"},
		"member": {"value": "user:developer@outlook.com"},
	}])

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_binding_with_org_email if {
	inp := build_input_bindings([{
		"role": {"value": "roles/viewer"},
		"members": [{"value": "user:employee@company.com"}],
	}])

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_member_with_org_email if {
	inp := build_input_members([{
		"role": {"value": "roles/editor"},
		"member": {"value": "user:admin@organization.gov"},
	}])

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_binding_with_service_account if {
	inp := build_input_bindings([{
		"role": {"value": "roles/compute.admin"},
		"members": [{"value": "serviceAccount:my-service@project.iam.gserviceaccount.com"}],
	}])

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_member_with_service_account if {
	inp := build_input_members([{
		"role": {"value": "roles/storage.admin"},
		"member": {"value": "serviceAccount:storage-service@project.iam.gserviceaccount.com"},
	}])

	res := check.deny with input as inp
	count(res) == 0
}

test_allow_binding_with_group if {
	inp := build_input_bindings([{
		"role": {"value": "roles/viewer"},
		"members": [{"value": "group:developers@company.com"}],
	}])

	res := check.deny with input as inp
	count(res) == 0
}

test_deny_mixed_members_with_personal_email if {
	inp := build_input_bindings([{
		"role": {"value": "roles/editor"},
		"members": [
			{"value": "user:good.user@company.com"},
			{"value": "user:bad.user@gmail.com"},
			{"value": "serviceAccount:service@project.iam.gserviceaccount.com"},
		],
	}])

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_multiple_personal_emails if {
	inp := {"google": {"iam": {"projects": [{
		"bindings": [{
			"role": {"value": "roles/viewer"},
			"members": [
				{"value": "user:user1@gmail.com"},
				{"value": "user:user2@yahoo.com"},
			],
			"__defsec_metadata": {"managed": true},
		}],
		"members": [{
			"role": {"value": "roles/editor"},
			"member": {"value": "user:user3@hotmail.com"},
			"__defsec_metadata": {"managed": true},
		}],
	}]}}}

	res := check.deny with input as inp
	count(res) == 3
}

test_deny_all_disallowed_domains if {
	disallowed_domains := {
		"gmail.com",
		"yahoo.com",
		"hotmail.com",
		"outlook.com",
		"aol.com",
		"icloud.com",
		"protonmail.com",
		"mail.com",
		"zoho.com",
	}

	every domain in disallowed_domains {
		inp := build_input_bindings([{
			"role": {"value": "roles/viewer"},
			"members": [{"value": sprintf("user:test@%s", [domain])}],
		}])

		res := check.deny with input as inp
		count(res) == 1
	}
}

build_input_bindings(bindings) := {"google": {"iam": {"projects": [{"bindings": add_managed_metadata(bindings)}]}}}

build_input_members(members) := {"google": {"iam": {"projects": [{"members": add_managed_metadata(members)}]}}}

add_managed_metadata(items) := [item |
	some i in items
	item := object.union(i, {"__defsec_metadata": {"managed": true}})
]
