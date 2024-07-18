package builtin.azure.authorization.azure0030_test

import rego.v1

import data.builtin.azure.authorization.azure0030 as check
import data.lib.test

test_deny_wildcard_action_with_all_scopes if {
	inp := build_input({
		"permissions": [{"actions": [{"value": "*"}]}],
		"assignablescopes": [{"value": "/"}],
	})
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_wildcard_action_with_specific_scope if {
	inp := build_input({
		"permissions": [{"actions": [{"value": "*"}]}],
		"assignablescopes": [{"value": "/subscriptions/0b1f6471-1bf0-4dda-aec3-111122223333"}],
	})
	res := check.deny with input as inp
	res == set()
}

test_allow_non_wildcard_action_with_all_scopes if {
	inp := build_input({
		"permissions": [{"actions": [{"value": "Microsoft.Resources/subscriptions/resourceGroups/read"}]}],
		"assignablescopes": [{"value": "/"}],
	})
	res := check.deny with input as inp
	res == set()
}

build_input(roledef) := {"azure": {"authorization": {"roledefinitions": [roledef]}}}
