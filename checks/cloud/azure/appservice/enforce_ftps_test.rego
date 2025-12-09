package builtin.azure.appservice.azure0071_test

import rego.v1

import data.builtin.azure.appservice.azure0071 as check

test_deny_all_allowed_ftp if {
	inp := {"azure": {"appservice": {"services": [{"site": {"ftpsstate": {"value": "AllAllowed"}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_deny_empty_ftps_state if {
	inp := {"azure": {"appservice": {"services": [{"site": {"ftpsstate": {"value": ""}}}]}}}
	res := check.deny with input as inp
	count(res) == 1
}

test_allow_ftps_only if {
	inp := {"azure": {"appservice": {"services": [{"site": {"ftpsstate": {"value": "FtpsOnly"}}}]}}}
	res := check.deny with input as inp
	res == set()
}

test_allow_disabled_ftp if {
	inp := {"azure": {"appservice": {"services": [{"site": {"ftpsstate": {"value": "Disabled"}}}]}}}
	res := check.deny with input as inp
	res == set()
}

test_allow_service_without_site if {
	inp := {"azure": {"appservice": {"services": [{}]}}}
	res := check.deny with input as inp
	res == set()
}
