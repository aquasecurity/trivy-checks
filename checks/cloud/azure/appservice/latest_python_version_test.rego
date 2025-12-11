package builtin.azure.appservice.azure0070_test

import rego.v1

import data.builtin.azure.appservice.azure0070 as check

test_deny_outdated_python_version if {
	inp := {"azure": {"appservice": {"services": [{"site": {"pythonversion": {"value": "3.8"}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_eol_python_version_37 if {
	inp := {"azure": {"appservice": {"services": [{"site": {"pythonversion": {"value": "3.7"}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_supported_python_version if {
	inp := {"azure": {"appservice": {"services": [{"site": {"pythonversion": {"value": "3.9"}}}]}}}
	res := check.deny with input as inp
	res == set()
}

test_allow_current_python_version if {
	inp := {"azure": {"appservice": {"services": [{"site": {"pythonversion": {"value": "3.12"}}}]}}}
	res := check.deny with input as inp
	res == set()
}

test_deny_patch_version_of_eol_python if {
	inp := {"azure": {"appservice": {"services": [{"site": {"pythonversion": {"value": "3.8.10"}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
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
