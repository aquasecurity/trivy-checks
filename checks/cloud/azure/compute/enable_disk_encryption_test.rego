package builtin.azure.compute.azure0038_test

import rego.v1

import data.builtin.azure.compute.azure0038 as check
import data.lib.test

test_deny_disk_encryption_disabled if {
	res := check.deny with input as build_input(false)
	count(res) == 1
}

test_allow_disk_encryption_enabled if {
	res := check.deny with input as build_input(true)
	res == set()
}

build_input(enabled) := {"azure": {"compute": {"manageddisks": [{"encryption": {"enabled": {"value": enabled}}}]}}}
