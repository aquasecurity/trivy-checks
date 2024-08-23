package builtin.azure.appservice.azure0002_test

import rego.v1

import data.builtin.azure.appservice.azure0002 as check
import data.lib.test

test_deny_identity_not_registerd if {
	inp := {"azure": {"appservice": {"services": [{"identity": {"type": {"value": ""}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_identity_type_is_not_specified if {
	inp := {"azure": {"appservice": {"services": [{"identity": {}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_identity_registerd if {
	inp := {"azure": {"appservice": {"services": [{"identity": {"type": {"value": "UserAssigned"}}}]}}}
	res := check.deny with input as inp
	res == set()
}
