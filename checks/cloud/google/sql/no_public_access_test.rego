package builtin.google.sql.google0017_test

import rego.v1

import data.builtin.google.sql.google0017 as check
import data.lib.test

test_deny_ipv4_enabled if {
	inp := build_input({"settings": {"ipconfiguration": {"enableipv4": {"value": true}}}})

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_ipv4_disabled if {
	inp := build_input({"settings": {"ipconfiguration": {"enableipv4": {"value": false}}}})

	check.deny with input as inp == set()
}

build_input(instance) := {"google": {"sql": {"instances": [instance]}}}
