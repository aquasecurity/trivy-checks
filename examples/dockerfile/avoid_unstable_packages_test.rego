package user.dockerfile.avoid_unstable_packages_test

import rego.v1

import data.user.dockerfile.avoid_unstable_packages as check

test_allow_package_with_pinned_version if {
	inp := {"Stages": [{
		"Name": "ubuntu",
		"Commands": [
			{
				"Cmd": "run",
				"Value": ["apt-get update && apt-get install curl=7.68.0-1ubuntu2.6"],
			},
			{
				"Cmd": "cmd",
				"Value": ["bash"],
			},
		],
	}]}

	res := check.deny with input as inp
	res == set()
}

test_deny_package_without_version if {
	inp := {"Stages": [{
		"Name": "ubuntu",
		"Commands": [
			{
				"Cmd": "run",
				"Value": ["apt-get update && apt-get install curl"],
			},
			{
				"Cmd": "cmd",
				"Value": ["bash"],
			},
		],
	}]}

	res := check.deny with input as inp
	count(res) = 1
}
