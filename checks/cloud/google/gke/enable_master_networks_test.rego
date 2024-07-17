package builtin.google.gke.google0061_test

import rego.v1

import data.builtin.google.gke.google0061 as check
import data.lib.test

test_deny_master_networks_disabled if {
	inp := {"google": {"gke": {"clusters": [{"masterauthorizednetworks": {"enabled": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_master_networks_enabled if {
	inp := {"google": {"gke": {"clusters": [{"masterauthorizednetworks": {"enabled": {"value": true}}}]}}}

	res := check.deny with input as inp
	res == set()
}
