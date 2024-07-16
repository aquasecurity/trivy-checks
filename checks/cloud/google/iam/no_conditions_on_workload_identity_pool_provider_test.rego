package builtin.google.iam.google0068_test

import rego.v1

import data.builtin.google.iam.google0068 as check
import data.lib.test

test_deny_empty_attribute_condition if {
	inp := build_input({"attributecondition": {"value": ""}})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_with_attribute_condition if {
	inp := build_input({"attributecondition": {"value": "assertion.repository_owner=='your-github-organization'"}})
	res := check.deny with input as inp
	count(res) == 0
}

build_input(provider) := {"google": {"iam": {"workloadidentitypoolproviders": [provider]}}}
