package builtin.azure.monitor.azure0033_test

import rego.v1

import data.builtin.azure.monitor.azure0033 as check
import data.lib.test

test_deny_log_profile_captures_only_write_activities if {
	inp := {"azure": {"monitor": {"logprofiles": [{"categories": [{"value": "Write"}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_log_profile_without_categories if {
	inp := {"azure": {"monitor": {"logprofiles": [{}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_log_profile_with_all_required_categories if {
	inp := {"azure": {"monitor": {"logprofiles": [{"categories": [
		{"value": "Write"},
		{"value": "Delete"},
		{"value": "Action"},
	]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
