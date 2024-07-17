package builtin.google.gke.google0063_test

import rego.v1

import data.builtin.google.gke.google0063 as check
import data.lib.test

test_deny_auto_repair_disabled if {
	inp := {"google": {"gke": {"clusters": [{"nodepools": [{"management": {"enableautorepair": {"value": false}}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_auto_repair_enabled if {
	inp := {"google": {"gke": {"clusters": [{"nodepools": [{"management": {"enableautorepair": {"value": true}}}]}]}}}

	res := check.deny with input as inp
	res == set()
}
