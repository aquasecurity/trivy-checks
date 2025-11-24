package builtin.azure.appservice.azure0069_test

import rego.v1

import data.builtin.azure.appservice.azure0069 as check

test_deny_outdated_php_version if {
	inp := {"azure": {"appservice": {"services": [{"site": {"phpversion": {"value": "7.4"}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_old_php_version if {
	inp := {"azure": {"appservice": {"services": [{"site": {"phpversion": {"value": "8.0"}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_latest_php_version if {
	inp := {"azure": {"appservice": {"services": [{"site": {"phpversion": {"value": check.latest_php_version}}}]}}}
	res := check.deny with input as inp
	res == set()
}

test_allow_no_php_configured if {
	inp := {"azure": {"appservice": {"services": [{"site": {"phpversion": {"value": ""}}}]}}}
	res := check.deny with input as inp
	res == set()
}

test_allow_service_without_site if {
	inp := {"azure": {"appservice": {"services": [{}]}}}
	res := check.deny with input as inp
	res == set()
}
