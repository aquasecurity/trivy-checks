package builtin.azure.appservice.azure0004_test

import rego.v1

import data.builtin.azure.appservice.azure0004 as check
import data.lib.test

test_deny_app_does_not_enforce_https if {
	inp := {"azure": {"appservice": {"functionapps": [{"httpsonly": {"value": false}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_httpsonly_is_not_specified if {
	inp := {"azure": {"appservice": {"functionapps": [{}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_app_enforces_https if {
	inp := {"azure": {"appservice": {"functionapps": [{"httpsonly": {"value": true}}]}}}
	res := check.deny with input as inp
	res == set()
}
