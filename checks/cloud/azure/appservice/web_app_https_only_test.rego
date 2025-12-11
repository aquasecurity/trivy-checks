package builtin.azure.appservice.azure0072_test

import rego.v1

import data.builtin.azure.appservice.azure0072 as check

test_deny_https_disabled if {
	inp := {"azure": {"appservice": {"services": [{"httpsonly": {"value": false}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_https_enabled if {
	inp := {"azure": {"appservice": {"services": [{"httpsonly": {"value": true}}]}}}
	res := check.deny with input as inp
	res == set()
}

test_allow_empty_services if {
	inp := {"azure": {"appservice": {"services": []}}}
	res := check.deny with input as inp
	res == set()
}
