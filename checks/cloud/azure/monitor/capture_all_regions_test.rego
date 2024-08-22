package builtin.azure.monitor.azure0032_test

import rego.v1

import data.builtin.azure.monitor.azure0032 as check
import data.lib.test

test_deny_profile_captures_only_one_region if {
	inp := {"azure": {"monitor": {"logprofiles": [{"locations": [{"value": "eastus"}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_profiles_without_locations if {
	inp := {"azure": {"monitor": {"logprofiles": [{}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_profiles_with_all_locations if {
	inp := {"azure": {"monitor": {"logprofiles": [{"locations": all_locations}]}}}

	res := check.deny with input as inp
	count(res) == 0
}

all_locations := locations if {
	locations := [
	{"value": region} |
		some region in check.required_regions
	]
}
