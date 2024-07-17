package builtin.google.gke.google0059_test

import rego.v1

import data.builtin.google.gke.google0059 as check
import data.lib.test

test_deny_private_cluster_disabled if {
	inp := {"google": {"gke": {"clusters": [{"privatecluster": {"enableprivatenodes": {"value": false}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_private_cluster_enabled if {
	inp := {"google": {"gke": {"clusters": [{"privatecluster": {"enableprivatenodes": {"value": true}}}]}}}

	res := check.deny with input as inp
	res == set()
}
