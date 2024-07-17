package builtin.google.iam.google0010_test

import rego.v1

import data.builtin.google.iam.google0010 as check
import data.lib.test

test_allow_auto_create_network_disabled if {
	inp := {"google": {"iam": {"projects": [{"autocreatenetwork": {"value": false}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_deny_auto_create_network_enabled if {
	inp := {"google": {"iam": {"projects": [{"autocreatenetwork": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}
