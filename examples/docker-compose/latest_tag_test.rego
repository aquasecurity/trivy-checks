package user.compose.latest_tag_test

import rego.v1

import data.user.compose.latest_tag as check

test_deny_latest_tag if {
	inp := {"services": {
		"web": {
			"build": ".",
			"ports": ["8000:5000"],
		},
		"redis": {"image": "redis:latest"},
	}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_specific_tag if {
	inp := {"services": {
		"web": {
			"build": ".",
			"ports": ["8000:5000"],
		},
		"redis": {"image": "redis:7.4"},
	}}

	res := check.deny with input as inp
	res == set()
}
