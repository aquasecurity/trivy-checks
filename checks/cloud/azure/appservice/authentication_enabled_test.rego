package builtin.azure.appservice.azure0003_test

import rego.v1

import data.builtin.azure.appservice.azure0003 as check
import data.lib.test

test_deny_authentication_disabled if {
	inp := {"azure": {"appservice": {"services": [{"authentication": {"enabled": {"value": false}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_authentication_is_not_specified if {
	inp := {"azure": {"appservice": {"services": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_authentication_enabled if {
	inp := {"azure": {"appservice": {"services": [{"authentication": {"enabled": {"value": true}}}]}}}
	res := check.deny with input as inp
	res == set()
}
