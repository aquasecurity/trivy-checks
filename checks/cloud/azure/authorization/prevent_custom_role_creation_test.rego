package builtin.azure.authorization.azure0052_test

import rego.v1

import data.builtin.azure.authorization.azure0052 as check

test_deny_role_with_explicit_roleDefinitions_write if {
	inp := build_input({"permissions": [{"actions": [{"value": "Microsoft.Authorization/roleDefinitions/write"}]}]})
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_role_with_authorization_wildcard if {
	inp := build_input({"permissions": [{"actions": [{"value": "Microsoft.Authorization/*"}]}]})
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_role_with_full_wildcard if {
	inp := build_input({"permissions": [{"actions": [{"value": "*"}]}]})
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_role_with_specific_read_permission if {
	inp := build_input({"permissions": [{"actions": [{"value": "Microsoft.Authorization/roleDefinitions/read"}]}]})
	res := check.deny with input as inp
	res == set()
}

test_allow_role_with_other_permissions if {
	inp := build_input({"permissions": [{"actions": [{"value": "Microsoft.Resources/subscriptions/resourceGroups/read"}]}]})
	res := check.deny with input as inp
	res == set()
}

test_allow_role_with_multiple_safe_permissions if {
	inp := build_input({"permissions": [{"actions": [
		{"value": "Microsoft.Authorization/roleDefinitions/read"},
		{"value": "Microsoft.Resources/subscriptions/resourceGroups/read"},
		{"value": "Microsoft.Storage/storageAccounts/read"},
	]}]})
	res := check.deny with input as inp
	res == set()
}

test_deny_role_with_mixed_permissions_including_dangerous if {
	inp := build_input({"permissions": [{"actions": [
		{"value": "Microsoft.Authorization/roleDefinitions/read"},
		{"value": "Microsoft.Authorization/roleDefinitions/write"},
		{"value": "Microsoft.Resources/subscriptions/resourceGroups/read"},
	]}]})
	res := check.deny with input as inp
	count(res) == 1
}

build_input(roledef) := {"azure": {"authorization": {"roledefinitions": [roledef]}}}
