package builtin.google.gke.google0058_test

import rego.v1

import data.builtin.google.gke.google0058 as check
import data.lib.test

test_deny_auto_upgrade_disabled if {
	inp := {"google": {"gke": {"clusters": [{"nodepools": [{"management": {"enableautoupgrade": {"value": false}}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_auto_upgrade_enabled if {
	inp := {"google": {"gke": {"clusters": [{"nodepools": [{"management": {"enableautoupgrade": {"value": true}}}]}]}}}

	res := check.deny with input as inp
	res == set()
}
