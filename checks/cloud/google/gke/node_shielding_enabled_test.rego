package builtin.google.gke.google0055_test

import rego.v1

import data.builtin.google.gke.google0055 as check
import data.lib.test

test_deny_cluster_shielded_nodes_disabled if {
	inp := {"google": {"gke": {"clusters": [{"enableshieldednodes": {"value": false}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_cluster_shielded_nodes_enabled if {
	inp := {"google": {"gke": {"clusters": [{"enableshieldednodes": {"value": true}}]}}}

	res := check.deny with input as inp
	res == set()
}
