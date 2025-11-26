package builtin.azure.appservice.azure0070_test

import rego.v1

import data.builtin.azure.appservice.azure0070 as check

test_deny_outdated_python_version if {
	inp := {"azure": {"appservice": {"services": [{"site": {"pythonversion": {"value": "3.8"}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_old_python_version if {
	inp := {"azure": {"appservice": {"services": [{"site": {"pythonversion": {"value": "3.9"}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_latest_python_version if {
	inp := {"azure": {"appservice": {"services": [{"site": {"pythonversion": {"value": check.latest_python_version}}}]}}}
	res := check.deny with input as inp
	res == set()
}

test_allow_no_python_configured if {
	inp := {"azure": {"appservice": {"services": [{"site": {"pythonversion": {"value": ""}}}]}}}
	res := check.deny with input as inp
	res == set()
}

test_allow_service_without_site if {
	inp := {"azure": {"appservice": {"services": [{}]}}}
	res := check.deny with input as inp
	res == set()
}
