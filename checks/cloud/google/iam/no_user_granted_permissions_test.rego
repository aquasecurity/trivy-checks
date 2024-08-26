package builtin.google.iam.google0003_test

import rego.v1

import data.builtin.google.iam.google0003 as check
import data.lib.test

user_member := {"value": "user:test@example.com"}

group_member := {"value": "group:test@example.com"}

test_deny_permissions_granted_to_project_users if {
	inp := {"google": {"iam": {"projects": [{"members": [{"member": user_member}]}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_permissions_granted_to_org_users if {
	inp := {"google": {"iam": {"organizations": [{"members": [{"member": user_member}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_permissions_granted_to_folder_users if {
	inp := {"google": {"iam": {"folders": [{"bindings": [{"members": [user_member]}]}]}}}

	res := check.deny with input as inp
	print(res)
	count(res) == 1
}

test_allow_permissions_granted_to_groups if {
	inp := {"google": {"iam": {
		"organizations": [{
			"members": [{"member": group_member}],
			"bindings": [{"members": [group_member]}],
		}],
		"projects": [{
			"members": [{"member": group_member}],
			"bindings": [{"members": [group_member]}],
		}],
		"folders": [{
			"members": [{"member": group_member}],
			"bindings": [{"members": [group_member]}],
		}],
	}}}

	res := check.deny with input as inp
	res == set()
}
